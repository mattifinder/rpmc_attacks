#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "pico/stdlib.h"
#include "pico/binary_info.h"
#include "mbedtls/md.h"
#include "hardware/spi.h"

#define RPMC_OP1_MSG_HEADER_LENGTH 4
#define RPMC_SIGNATURE_LENGTH 32
#define RPMC_COUNTER_LENGTH 4
#define RPMC_KEY_DATA_LENGTH 4
#define RPMC_TAG_LENGTH 12
#define RPMC_HMAC_KEY_LENGTH 32
#define RPMC_TRUNCATED_SIG_LENGTH 28
#define OP1_OPCODE UINT8_C(0x9b)
#define OP2_OPCODE UINT8_C(0x96)

// OP1 commands
#define RPMC_UPDATE_HMAC_KEY_MSG_LENGTH (RPMC_OP1_MSG_HEADER_LENGTH + RPMC_KEY_DATA_LENGTH + RPMC_SIGNATURE_LENGTH)
#define RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH (RPMC_OP1_MSG_HEADER_LENGTH + RPMC_COUNTER_LENGTH + RPMC_SIGNATURE_LENGTH)
#define RPMC_GET_MONOTONIC_COUNTER_MSG_LENGTH (RPMC_OP1_MSG_HEADER_LENGTH + RPMC_TAG_LENGTH + RPMC_SIGNATURE_LENGTH)

// OP2 commands
#define RPMC_READ_DATA_MSG_LENGTH 2
#define RPMC_READ_DATA_ANSWER_LENGTH (1 + RPMC_TAG_LENGTH + RPMC_COUNTER_LENGTH + RPMC_SIGNATURE_LENGTH)

#define TARGET_BAUDRATE (5U * 1000 * 1000) // 12 mhz 

static inline void cs_select(uint cs_pin) {
    asm volatile("nop \n nop \n nop"); // FIXME
    gpio_put(cs_pin, 0);
    asm volatile("nop \n nop \n nop"); // FIXME
}

static inline void cs_deselect(uint cs_pin) {
    asm volatile("nop \n nop \n nop"); // FIXME
    gpio_put(cs_pin, 1);
    asm volatile("nop \n nop \n nop"); // FIXME
}

void spi_transaction(spi_inst_t * const spi_connection, const unsigned int cs_pin,
                     const uint8_t * const in_buffer, const size_t in_length,
                     uint8_t * out_buffer, const size_t out_length)
{
    cs_select(cs_pin);

    spi_write_blocking(spi_connection, in_buffer, in_length);

    spi_read_blocking(spi_connection, 0, out_buffer, out_length);

    cs_deselect(cs_pin);
}

uint8_t get_rpmc_status(spi_inst_t * const spi_connection, const unsigned int cs_pin)
{
    const uint8_t get_status_msg[RPMC_READ_DATA_MSG_LENGTH] = {
        OP2_OPCODE,
        0,
    };
    uint8_t status;

    spi_transaction(spi_connection, cs_pin, get_status_msg, RPMC_READ_DATA_MSG_LENGTH, &status, 1);

    return status;
}

void poll_until_finished(spi_inst_t * const spi_connection, const unsigned int cs_pin)
{
    uint8_t status;

    do {
        // according to specs this is the typical time it take to increment the counter
        sleep_us(80);
        status = get_rpmc_status(spi_connection, cs_pin);
    } while (status & 1);
}

int update_hmac_key_register(spi_inst_t * const spi_connection,
                             const unsigned int cs_pin,
                             const uint8_t target_counter,
                             const uint8_t hmac_key[RPMC_HMAC_KEY_LENGTH],
                             const uint8_t key_data[RPMC_KEY_DATA_LENGTH])
{
    const unsigned int signature_offset = RPMC_OP1_MSG_HEADER_LENGTH + RPMC_KEY_DATA_LENGTH;
    uint8_t msg[RPMC_UPDATE_HMAC_KEY_MSG_LENGTH] = {
        OP1_OPCODE,
        0x01,
        target_counter,
        0x0
    };
    memcpy(msg + RPMC_OP1_MSG_HEADER_LENGTH, key_data, RPMC_KEY_DATA_LENGTH);

    if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), hmac_key, RPMC_HMAC_KEY_LENGTH, msg, signature_offset, msg + signature_offset)) {
        printf("Error: could not sign update hmac key msg\n");
        return 1;
    }

    spi_transaction(spi_connection, cs_pin, msg, RPMC_UPDATE_HMAC_KEY_MSG_LENGTH, NULL, 0);
    poll_until_finished(spi_connection, cs_pin);

    return get_rpmc_status(spi_connection, cs_pin) != 0x80;
}

int get_counter_value(spi_inst_t * const spi_connection,
                      const unsigned int cs_pin,
                      const uint8_t target_counter,
                      const uint8_t hmac_key[RPMC_HMAC_KEY_LENGTH],
                      uint32_t * value)
{
	const unsigned int signature_offset = RPMC_OP1_MSG_HEADER_LENGTH + RPMC_TAG_LENGTH;
    // Tag is whatever it gets initialized as
    uint8_t msg[RPMC_GET_MONOTONIC_COUNTER_MSG_LENGTH] = {
		OP1_OPCODE, // Opcode
		0x03, // CmdType
		target_counter, // CounterAddr
		0 // Reserved
	};

    if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), hmac_key, RPMC_HMAC_KEY_LENGTH, msg, signature_offset, msg + signature_offset)) {
        printf("Error: can't sign hmac get counter message\n");
        return 1;
    };

    spi_transaction(spi_connection, cs_pin, msg, RPMC_GET_MONOTONIC_COUNTER_MSG_LENGTH, NULL, 0);
    poll_until_finished(spi_connection, cs_pin);

    // Read the counter value from read data message
    const uint8_t get_status_msg[RPMC_READ_DATA_MSG_LENGTH] = {
        OP2_OPCODE,
        0,
    };
    const unsigned int counter_offset = 1 + RPMC_TAG_LENGTH;
    uint8_t full_status[RPMC_READ_DATA_ANSWER_LENGTH];
    
    spi_transaction(spi_connection, cs_pin, get_status_msg, RPMC_READ_DATA_MSG_LENGTH, full_status, RPMC_READ_DATA_ANSWER_LENGTH);
    if (full_status[0] != 0x80) {
        printf("Error: could not read counter value\n");
        return 1;
    }

    *value = full_status[counter_offset] ;
    *value = (*value << 8) | full_status[counter_offset + 1];
    *value = (*value << 8) | full_status[counter_offset + 2];
    *value = (*value << 8) | full_status[counter_offset + 3];

    return 0;
}

int increment_counter(spi_inst_t * const spi_connection,
                      const unsigned int cs_pin,
                      const uint8_t target_counter,
                      const uint8_t hmac_key[RPMC_HMAC_KEY_LENGTH],
                      const uint32_t curr_value)
{
    const unsigned int signature_offset = RPMC_OP1_MSG_HEADER_LENGTH + RPMC_COUNTER_LENGTH;
	unsigned char msg[RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH] = {
        OP1_OPCODE, // Opcode
		0x02, // CmdType
		target_counter, // CounterAddr
		0, // Reserved
        curr_value >> 24,
        curr_value >> 16,
        curr_value >> 8,
        curr_value
    };

    if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), hmac_key, RPMC_HMAC_KEY_LENGTH, msg, signature_offset, msg + signature_offset)) {
        printf("Error: can't sign hmac get counter message\n");
        return 1;
    };

    spi_transaction(spi_connection, cs_pin, msg, RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH, NULL, 0);
    poll_until_finished(spi_connection, cs_pin);

    return get_rpmc_status(spi_connection, cs_pin) != 0x80;
}

int loop(spi_inst_t * const spi_connection, const unsigned int cs_pin)
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
    printf("Updated hmac key register\n");

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

        uint32_t next_counter_value = curr_counter_value + 1;
        if (((next_counter_value) / 1000000) > (curr_counter_value / 1000000)) {
            time_t next_time = time(NULL);
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

    int ret = loop(spi0, PICO_DEFAULT_SPI_CSN_PIN);
exit:
    spi_deinit(spi0);
    return ret;
}
