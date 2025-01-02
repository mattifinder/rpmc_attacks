#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "pico/stdlib.h"
#include "pico/binary_info.h"
#include "mbedtls/md.h"
#include "hardware/spi.h"
#include "pico/cyw43_arch.h"
#include "rpmc_ops.h"

inline int rpmc_ops_spi_write(void * spi_connection, const uint8_t * write_buffer, size_t write_amount)
{
    return spi_write_blocking((spi_inst_t *)spi_connection, write_buffer, write_amount);
}

inline int rpmc_ops_spi_read(void * spi_connection, uint8_t fill_char, uint8_t * read_buffer, size_t read_amount)
{
    return spi_read_blocking((spi_inst_t *)spi_connection, fill_char, read_buffer, read_amount);
}

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

    uint32_t curr_counter_value;
    if (get_counter_value(spi_connection, cs_pin, target_counter, hmac_key_register, &curr_counter_value)) {
        printf("Error: could not get the current monotonic counter value for counter %u\n", target_counter);
        return 1;
    }
    printf("Start counter value %u for counter %u\n", curr_counter_value, target_counter);

    bool led_state = false;
    while (curr_counter_value < UINT32_MAX) {
        if (increment_counter(spi_connection, cs_pin, target_counter, hmac_key_register, curr_counter_value)) {
            printf("Error: increment failed at counter value %u for counter %u\n", curr_counter_value, target_counter);
            return 1;
        }

        const uint32_t next_counter_value = curr_counter_value + 1;
        if ((next_counter_value / 10000) > (curr_counter_value / 10000)) {
            led_state = !led_state;
            cyw43_arch_gpio_put(led_pin, led_state);
        }

        curr_counter_value = next_counter_value;
    }

    return 0;
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

    for (int ret = 1; ret != 0; ret = loop(spi0, CYW43_WL_GPIO_LED_PIN, PICO_DEFAULT_SPI_CSN_PIN))
        ;

    spi_deinit(spi0);

    while (true) {
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, true);
        sleep_ms(500);
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, false);
        sleep_ms(500);
    }

    return 0;
}
