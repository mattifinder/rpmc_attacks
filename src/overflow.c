#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "pico/stdlib.h"
#include "pico/binary_info.h"
#include "mbedtls/md.h"
#include "hardware/spi.h"
#include "pico/cyw43_arch.h"
#include "rpmc_ops.h"

void toggle_led(unsigned int led_pin) 
{
    static bool value = false;
    cyw43_arch_gpio_put(led_pin, value);
    value = !value;
}

int loop(spi_inst_t * const spi_connection, const unsigned int led_pin, const unsigned int cs_pin)
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
    
    if (update_hmac_key_register(spi_connection, cs_pin, target_counter, hmac_key_register, key_data)) {
        printf("Error: could not set initialize hmac key register\n");
        return 1;
    }
    printf("Updated hmac key register for counter %u\n", target_counter);

    uint32_t curr_counter_value;
    if (get_counter_value(spi_connection, cs_pin, target_counter, hmac_key_register, &curr_counter_value)) {
        printf("Error: could not get the current monotonic counter value for counter %u\n", target_counter);
        return 1;
    }
    printf("Start counter value %u for counter %u\n", curr_counter_value, target_counter);

    time_t start_time = time(NULL);
    while (curr_counter_value < 4000000000U) {
        if (increment_counter(spi_connection, cs_pin, target_counter, hmac_key_register, curr_counter_value)) {
            printf("Error: increment failed at counter value %u for counter %u\n", curr_counter_value, target_counter);
            return 1;
        }

        const uint32_t next_counter_value = curr_counter_value + 1;
        if (((next_counter_value) / 10000) > (curr_counter_value / 10000)) {
            toggle_led(led_pin);
        }

        if (((next_counter_value) / 1000000) > (curr_counter_value / 1000000)) {
            const time_t next_time = time(NULL);
            printf("Incrementing the counter to %u took %lf seconds\n", next_counter_value, difftime(next_time, start_time));
            start_time = next_time;
        }
        curr_counter_value = next_counter_value;
    }

    return 0;
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

    init_spi_transmission_function((int (*)(void *, uint8_t, const uint8_t *, size_t))spi_read_blocking,
                                   (int (*)(void *, const uint8_t *, size_t))spi_write_blocking);

    int ret = loop(spi0, CYW43_WL_GPIO_LED_PIN, PICO_DEFAULT_SPI_CSN_PIN);
exit:
    spi_deinit(spi0);
    return ret;
}
