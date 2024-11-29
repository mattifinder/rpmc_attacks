#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/binary_info.h"
#include "rpmc_ops.h"
#include "mbedtls/md.h"
#include "clock_spi.pio.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "hardware/vreg.h"

struct pio_instance {
    PIO pio;
    unsigned int state_machine;
    int load_offset;
};

int __time_critical_func(pio_spi_write)(struct pio_instance * const spi, const uint8_t * src, const size_t len)
{
    size_t tx_remain = len;
    size_t rx_remain = len;

    // Do 8 bit accesses on FIFO, so that write data is byte-replicated. This
    // gets us the left-justification for free (for MSB-first shift-out)
    io_wo_8 *txfifo = (io_wo_8 *) &spi->pio->txf[spi->state_machine];
    io_ro_8 *rxfifo = (io_ro_8 *) &spi->pio->rxf[spi->state_machine];

    while (tx_remain > 0 || rx_remain > 0) {
        if (tx_remain > 0 && !pio_sm_is_tx_fifo_full(spi->pio, spi->state_machine)) {
            *txfifo = *src++;
            --tx_remain;
        }

        if (rx_remain > 0 && !pio_sm_is_rx_fifo_empty(spi->pio, spi->state_machine)) {
            (void) *rxfifo;
            --rx_remain;
        }
    }
}

inline int rpmc_ops_spi_write(void * spi_connection, const uint8_t * write_buffer, size_t write_amount)
{
    return pio_spi_write((struct pio_instance *)spi_connection, write_buffer, write_amount);
}

int __time_critical_func(pio_spi_recieve)(struct pio_instance * const spi, const uint8_t write_placeholder, uint8_t * dest, const size_t len)
{
    size_t tx_remain = len;
    size_t rx_remain = len;

    // Do 8 bit accesses on FIFO, so that write data is byte-replicated. This
    // gets us the left-justification for free (for MSB-first shift-out)
    io_wo_8 *txfifo = (io_wo_8 *) &spi->pio->txf[spi->state_machine];
    io_ro_8 *rxfifo = (io_ro_8 *) &spi->pio->rxf[spi->state_machine];

    while (tx_remain > 0 || rx_remain > 0) {
        if (tx_remain > 0 && !pio_sm_is_tx_fifo_full(spi->pio, spi->state_machine)) {
            *txfifo = write_placeholder;
            --tx_remain;
        }

        if (rx_remain > 0 && !pio_sm_is_rx_fifo_empty(spi->pio, spi->state_machine)) {
            *dest++ = *rxfifo;
            --rx_remain;
        }
    }
}

inline int rpmc_ops_spi_read(void * spi_connection, uint8_t fill_char, uint8_t * read_buffer, size_t read_amount)
{
    return pio_spi_recieve((struct pio_instance *)spi_connection, fill_char, read_buffer, read_amount);
}

static void transmit_glitch_cycles(struct pio_instance * const spi_connection, const uint32_t glitch_cycles)
{
    // There should be no current tranmission going on
    // Clear the fifos just in case
    pio_sm_clear_fifos(spi_connection->pio, spi_connection->state_machine);
    
    // Jump to exploit code and give it the cycles to glitch after
    pio_sm_exec(spi_connection->pio, spi_connection->state_machine, pio_encode_jmp(spi_connection->load_offset + spi_with_setup_for_glitch_offset_setup_glitch));
    pio_sm_put_blocking(spi_connection->pio, spi_connection->state_machine, glitch_cycles);
}

static int get_all_counter_values(struct pio_instance * const spi_connection,
                                  const uint8_t hmac_key[RPMC_HMAC_KEY_LENGTH],
                                  const unsigned int cs_pin,
                                  const size_t num_counters,
                                  uint32_t values[num_counters])
{
    for (uint8_t counter = 0; counter < num_counters; counter++) {
        if (get_counter_value(spi_connection, cs_pin, counter, hmac_key, values++)) {
            return 1;
        }
    }
    return 0;
}

static void print_glitch_result(const size_t cycles, const char * result, const uint8_t status)
{
    printf("Glitch after %u changes of clk: %s (status: 0x%02x)\n", cycles, result, status);
}

static int glitch_increment(struct pio_instance * const spi_connection,
                            const uint8_t const hmac_key[RPMC_HMAC_KEY_LENGTH],
                            const unsigned int cs_pin,
                            const uint8_t target_counter,
                            const size_t num_counters,
                            const uint32_t const old_counter_values[num_counters])
{
    uint32_t * new_counter_values = malloc(sizeof(uint32_t) * num_counters);
    if (new_counter_values == NULL) {
        printf("Could not allocate new counter values\n");
        return 1;
    }
    int ret = 0;
    const uint32_t exploit_value = 0;
    const size_t signature_offset = RPMC_OP1_MSG_HEADER_LENGTH + RPMC_COUNTER_LENGTH;
    uint8_t increment_msg[RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH] = {
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
                        hmac_key,
                        RPMC_HMAC_KEY_LENGTH,
                        increment_msg,
                        signature_offset,
                        increment_msg + signature_offset)) {
        printf("Error: can't sign hmac increment counter message\n");
        ret = 1;
        goto cleanup;
    };

    printf("Trying to glitch increment:\n");
    // This tries a clock glitch after every cycle
    for (size_t glitch_cycles = 0; glitch_cycles < RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH * 8 * 2; glitch_cycles++) {
        // Send this to clear any previous request results from the device
        // Without this glitching after 7 and 13 return successful status, because previous was successfull and command is not read correctly
        spi_transaction(spi_connection, cs_pin, increment_msg, RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH, NULL, 0);
        
        transmit_glitch_cycles(spi_connection, glitch_cycles);

        spi_transaction(spi_connection, cs_pin, increment_msg, RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH, NULL, 0);

        poll_until_finished(spi_connection, cs_pin);

        const uint8_t status = get_rpmc_status(spi_connection, cs_pin);
        if (get_all_counter_values(spi_connection, hmac_key, cs_pin, num_counters, new_counter_values)) {
            printf("Error: could not get new counter values\n");
            ret = 1;
            goto cleanup;
        }

        if (status == 0x80 
            || memcmp(old_counter_values, new_counter_values, num_counters * sizeof(*old_counter_values)) != 0) {
            print_glitch_result(glitch_cycles, "changed counter", status);
            for (size_t counter = 0; counter < num_counters; counter++) {
                printf("                        counter %u: %u -> %u\n", counter, old_counter_values[counter], new_counter_values[counter]);
            }
        } else if (status != 0x10) {
            print_glitch_result(glitch_cycles, "unexpected status code", status);
        }
    }    
    printf("Done\n");

cleanup:
    free(new_counter_values);
    return ret;
}

static int glitch_get(struct pio_instance * const spi_connection,
                      const uint8_t const hmac_key[RPMC_HMAC_KEY_LENGTH],
                      const unsigned int cs_pin,
                      const uint8_t target_counter,
                      const uint32_t current_value)
{
    const size_t tag_offset = RPMC_OP1_MSG_HEADER_LENGTH;
    const size_t signature_offset = tag_offset + RPMC_TAG_LENGTH;
    uint8_t get_msg[RPMC_GET_MONOTONIC_COUNTER_MSG_LENGTH] = {
		OP1_OPCODE, // Opcode
		0x03, // CmdType
		target_counter, // CounterAddr
		0 // Reserved
	};
    // Set tag to all 1
    memset(get_msg + tag_offset, 0xff, RPMC_TAG_LENGTH);
    if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                        hmac_key,
                        RPMC_HMAC_KEY_LENGTH,
                        get_msg,
                        signature_offset,
                        get_msg + signature_offset)) {
        printf("Error: can't sign hmac get counter message\n");
        return 1;
    };

    printf("Trying to glitch get:\n");
    for (size_t glitch_cycles = 0; glitch_cycles < RPMC_GET_MONOTONIC_COUNTER_MSG_LENGTH * 8 * 2; glitch_cycles++) {
        transmit_glitch_cycles(spi_connection, glitch_cycles);

        spi_transaction(spi_connection, cs_pin, get_msg, RPMC_GET_MONOTONIC_COUNTER_MSG_LENGTH, NULL, 0);

        poll_until_finished(spi_connection, cs_pin);

        struct rpmc_status_register result;
        get_full_rpmc_status(spi_connection, cs_pin, &result);

        uint8_t expected_signature[RPMC_SIGNATURE_LENGTH];
        if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                            hmac_key,
                            RPMC_HMAC_KEY_LENGTH,
                            ((uint8_t *)&result) + 1,
                            RPMC_TAG_LENGTH + RPMC_COUNTER_LENGTH,
                            expected_signature)) {
            printf("Error: can't calculate expected signature\n");
            return 1;
        };

        if (result.return_code != 0x80) {
            print_glitch_result(glitch_cycles, "operation failed", result.return_code);
        } else if (memcmp(get_msg + tag_offset, result.tag, RPMC_TAG_LENGTH) != 0) {
            print_glitch_result(glitch_cycles, "tag differs", result.return_code);
        } else if (memcmp(expected_signature, result.signature, RPMC_SIGNATURE_LENGTH) != 0) {
            print_glitch_result(glitch_cycles, "signature differs", result.return_code);
        } else if (current_value != ((result.counter_data[0] << 24) | (result.counter_data[1] << 16) | (result.counter_data[2] << 8) | result.counter_data[3])) {
            print_glitch_result(glitch_cycles, "counter value is wrong", result.return_code);
        }
    }
    printf("Done\n");

    return 0;
}

static int loop(struct pio_instance * const spi_connection, const unsigned int cs_pin)
{
    const uint8_t root_key[RPMC_HMAC_KEY_LENGTH] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const uint8_t key_data[RPMC_KEY_DATA_LENGTH] = {0x00, 0x00, 0x00, 0x00};
    const size_t num_counters = 4;
    const uint8_t target_counter = 0;

    uint8_t hmac_key_register[RPMC_HMAC_KEY_LENGTH];
    if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), root_key, RPMC_HMAC_KEY_LENGTH, key_data, RPMC_KEY_DATA_LENGTH, hmac_key_register)) {
        printf("Error: could not generate the hmac key\n");
        return 1;
    }

    // Initialize hmac key register for all counters
    for (uint8_t counter = 0; counter < num_counters; counter++) {
        if (update_hmac_key_register(spi_connection, cs_pin, counter, hmac_key_register, key_data)) {
            printf("Error: could not initialize hmac key register\n");
            return 1;
        }
    }

    // Read out all previous values in case we are able to change one
    uint32_t old_counter_values[num_counters];
    if (get_all_counter_values(spi_connection, hmac_key_register, cs_pin, num_counters, old_counter_values)) {
        printf("Error: could not get old counter values\n");
        return 1;
    }
    
    int ret = glitch_increment(spi_connection, hmac_key_register, cs_pin, target_counter, num_counters, old_counter_values);
    if (ret)
        return ret;

    ret = glitch_get(spi_connection, hmac_key_register, cs_pin, target_counter, old_counter_values[target_counter]);
    if (ret)
        return ret;

    return 0;
}

static void pio_spi_init(PIO pio,
                         uint sm,
                         uint prog_offs,
                         uint n_bits,
                         float clkdiv,
                         uint pin_sck,
                         uint pin_mosi,
                         uint pin_miso)
{
    pio_sm_config c = spi_with_setup_for_glitch_program_get_default_config(prog_offs);

    sm_config_set_out_pins(&c, pin_mosi, 1);
    sm_config_set_in_pins(&c, pin_miso);
    sm_config_set_sideset_pins(&c, pin_sck);
    // Only support MSB-first in this example code (shift to left, auto push/pull, threshold=nbits)
    sm_config_set_out_shift(&c, false, true, n_bits);
    sm_config_set_in_shift(&c, false, true, n_bits);
    sm_config_set_clkdiv(&c, clkdiv);

    // MOSI, SCK output are low, MISO is input
    pio_sm_set_pins_with_mask(pio, sm, 0, (1u << pin_sck) | (1u << pin_mosi));
    pio_sm_set_pindirs_with_mask(pio, sm, (1u << pin_sck) | (1u << pin_mosi), (1u << pin_sck) | (1u << pin_mosi) | (1u << pin_miso));
    pio_gpio_init(pio, pin_mosi);
    pio_gpio_init(pio, pin_miso);
    pio_gpio_init(pio, pin_sck);

    // SPI is synchronous, so bypass input synchroniser to reduce input delay.
    hw_set_bits(&pio->input_sync_bypass, 1u << pin_miso);

    pio_sm_init(pio, sm, prog_offs, &c);
    pio_sm_set_enabled(pio, sm, true);
}

static inline float freq_to_clkdiv(uint32_t freq) {
    float div = (double)clock_get_hz(clk_sys) / (freq * PIO_SPI_CYCLES_PER_BIT);

    if (div < 1.0)
        div = 1.0;
    if (div > 65536.0)
        div = 65536.0;

    return div;
}

int main()
{
    vreg_set_voltage(VREG_VOLTAGE_1_30);
    set_sys_clock_khz(200000, true);
    stdio_init_all();
    sleep_ms(1000);
    printf("Device is starting\n");

    struct pio_instance spi_pio_instance = {
        .pio = pio0,
        .state_machine = 0
    };

    spi_pio_instance.load_offset = pio_add_program(spi_pio_instance.pio, &spi_with_setup_for_glitch_program);
    if (spi_pio_instance.load_offset < 0) {
        printf("Error: could not add pio programm\n");
        return 1;
    }

    pio_spi_init(spi_pio_instance.pio,
                 spi_pio_instance.state_machine,
                 spi_pio_instance.load_offset,
                 8,
                 1.0, // run as fast as possible
                 PICO_DEFAULT_SPI_SCK_PIN, 
                 PICO_DEFAULT_SPI_TX_PIN, 
                 PICO_DEFAULT_SPI_RX_PIN);
    bi_decl(bi_1pin_with_name(PICO_DEFAULT_SPI_SCK_PIN, "SPI CLK"));
    bi_decl(bi_1pin_with_name(PICO_DEFAULT_SPI_TX_PIN, "SPI MOSI"));
    bi_decl(bi_1pin_with_name(PICO_DEFAULT_SPI_RX_PIN, "SPI MISO"));

    // Chip select is active-low, so we'll initialise it to a driven-high state
    gpio_init(PICO_DEFAULT_SPI_CSN_PIN);
    gpio_put(PICO_DEFAULT_SPI_CSN_PIN, 1);
    gpio_set_dir(PICO_DEFAULT_SPI_CSN_PIN, GPIO_OUT);
    // Make the CS pin available to picotool
    bi_decl(bi_1pin_with_name(PICO_DEFAULT_SPI_CSN_PIN, "SPI CS"));

    int ret = loop(&spi_pio_instance, PICO_DEFAULT_SPI_CSN_PIN);

    while (true)
        ;

    return ret;
}
