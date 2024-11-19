#ifndef _RPMC_OPS_H_
#define _RPMC_OPS_H_

#include <stdint.h>
#include <stddef.h>

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

// set the internal transmission functions must be called before any operation
// spi connection is always passed to the function in the first arg
void init_spi_transmission_function(int (*read_func)(void *, uint8_t, const uint8_t *, size_t),
                                    int (*write_func)(void *, const uint8_t *, size_t));

void spi_transaction(void * spi_connection, unsigned int cs_pin,
                     const uint8_t * in_buffer, size_t in_length,
                     uint8_t * out_buffer, size_t out_length);

uint8_t get_rpmc_status(void * spi_connection, unsigned int cs_pin);

void poll_until_finished(void * spi_connection, unsigned int cs_pin);

int update_hmac_key_register(void * spi_connection,
                             unsigned int cs_pin,
                             uint8_t target_counter,
                             const uint8_t hmac_key[RPMC_HMAC_KEY_LENGTH],
                             const uint8_t key_data[RPMC_KEY_DATA_LENGTH]);

int get_counter_value(void * spi_connection,
                      unsigned int cs_pin,
                      uint8_t target_counter,
                      const uint8_t hmac_key[RPMC_HMAC_KEY_LENGTH],
                      uint32_t * value);

int increment_counter(void * spi_connection,
                      unsigned int cs_pin,
                      uint8_t target_counter,
                      const uint8_t hmac_key[RPMC_HMAC_KEY_LENGTH],
                      uint32_t curr_value);

#endif // _RPMC_OPS_H_
