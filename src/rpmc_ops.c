#include "rpmc_ops.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/spi.h"
#include "mbedtls/md.h"


static int (*spi_read)(void *, uint8_t, const uint8_t *, size_t) = NULL;
static int (*spi_write)(void *, const uint8_t *, size_t) = NULL;


void init_spi_transmission_function(int (*read_func)(void *, uint8_t, const uint8_t *, size_t),
                                    int (*write_func)(void *, const uint8_t *, size_t)) 
{
    spi_read = read_func;
    spi_write = write_func;
}

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

void spi_transaction(void * const spi_connection, const unsigned int cs_pin,
                     const uint8_t * const in_buffer, const size_t in_length,
                     uint8_t * out_buffer, const size_t out_length)
{
    hard_assert(spi_read != NULL);
    hard_assert(spi_write != NULL);

    cs_select(cs_pin);

    if (in_buffer != NULL)
        spi_write(spi_connection, in_buffer, in_length);

    if (out_buffer != NULL)
        spi_read(spi_connection, 0, out_buffer, out_length);

    cs_deselect(cs_pin);
}

uint8_t get_rpmc_status(void * const spi_connection, const unsigned int cs_pin)
{
    const uint8_t get_status_msg[RPMC_READ_DATA_MSG_LENGTH] = {
        OP2_OPCODE,
        0,
    };
    uint8_t status;

    spi_transaction(spi_connection, cs_pin, get_status_msg, RPMC_READ_DATA_MSG_LENGTH, &status, 1);

    return status;
}

void poll_until_finished(void * const spi_connection, const unsigned int cs_pin)
{
    uint8_t status;

    do {
        // according to specs this is the typical time it take to increment the counter
        sleep_us(80);
        status = get_rpmc_status(spi_connection, cs_pin);
    } while (status & 1);
}

int update_hmac_key_register(void * const spi_connection,
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

int get_counter_value(void * const spi_connection,
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

int increment_counter(void * const spi_connection,
                      const unsigned int cs_pin,
                      const uint8_t target_counter,
                      const uint8_t hmac_key[RPMC_HMAC_KEY_LENGTH],
                      const uint32_t curr_value)
{
    const unsigned int signature_offset = RPMC_OP1_MSG_HEADER_LENGTH + RPMC_COUNTER_LENGTH;
	uint8_t msg[RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH] = {
        OP1_OPCODE, // Opcode
		0x02, // CmdType
		target_counter, // CounterAddr
		0, // Reserved
        (curr_value >> 24) & 0xff,
        (curr_value >> 16) & 0xff,
        (curr_value >> 8) & 0xff,
        curr_value & 0xff
    };

    if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), hmac_key, RPMC_HMAC_KEY_LENGTH, msg, signature_offset, msg + signature_offset)) {
        printf("Error: can't sign hmac increment counter message\n");
        return 1;
    };

    spi_transaction(spi_connection, cs_pin, msg, RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH, NULL, 0);
    poll_until_finished(spi_connection, cs_pin);

    return get_rpmc_status(spi_connection, cs_pin) != 0x80;
}
