#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "pico/stdlib.h"
#include "pico/binary_info.h"
#include "mbedtls/md.h"
#include "hardware/spi.h"
#include "pico/cyw43_arch.h"
#include "rpmc_ops.h"

#define PIN_MISO 4
#define PIN_MOSI 3
#define PIN_SCK 2
#define PIN_CS 5
#define PIN_1V8_OE 21
#define PIN_DIR_A 22
#define PIN_DIR_B 20

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
        if ((next_counter_value ^ curr_counter_value) & (1 << 14)) {
            led_state = !led_state;
            cyw43_arch_gpio_put(led_pin, led_state);
            printf("Successfully incremented to %u\n", curr_counter_value);
        }

        curr_counter_value = next_counter_value;
    }

    return 0;
}

int main()
{
    bi_decl(bi_1pin_with_name(PIN_CS, "CS"));
    bi_decl(bi_3pins_with_func(PIN_MISO, PIN_SCK, PIN_MOSI, GPIO_FUNC_SPI));
    bi_decl(bi_3pins_with_names(PIN_DIR_A, "3V3 to 1V8 enable", PIN_DIR_B, "1V8 to 3V3 enable", PIN_1V8_OE, "Logic converter output enable"));

    stdio_init_all();

    hard_assert(cyw43_arch_init() == 0);

    spi_init(spi0, 1000 * 1000);
    gpio_set_function(PIN_MISO, GPIO_FUNC_SPI);
    gpio_set_function(PIN_SCK, GPIO_FUNC_SPI);
    gpio_set_function(PIN_MOSI, GPIO_FUNC_SPI);

    // Initialize CS
    gpio_init(PIN_CS);
    gpio_put(PIN_CS, 1);
    gpio_set_dir(PIN_CS, GPIO_OUT);

    // Initialize logic converter
    gpio_init(PIN_DIR_A);
    gpio_put(PIN_DIR_A, 1);
    gpio_set_dir(PIN_DIR_A, GPIO_OUT);
    
    gpio_init(PIN_DIR_B);
    gpio_put(PIN_DIR_B, 0);
    gpio_set_dir(PIN_DIR_B, GPIO_OUT);
    
    gpio_init(PIN_1V8_OE);
    gpio_put(PIN_1V8_OE, 0);
    gpio_set_dir(PIN_1V8_OE, GPIO_OUT);

    while (loop(spi0, CYW43_WL_GPIO_LED_PIN, PIN_CS))
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
