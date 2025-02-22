/**
 * Written by Matti Finder - matti.finder@gmail.com
 *
 * Licensed under GPLv3
 *
 * Heavily based on pico-serprog:
 *  https://github.com/stacksmashing/pico-serprog
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "pico/stdlib.h"
#include "pico/binary_info.h"
#include "pico/multicore.h"
#include "hardware/spi.h"

/* According to Serial Flasher Protocol Specification - version 1 */
#define S_ACK 0x06
#define S_NAK 0x15
#define S_CMD_NOP		0x00	/* No operation					*/
#define S_CMD_Q_IFACE		0x01	/* Query interface version			*/
#define S_CMD_Q_CMDMAP		0x02	/* Query supported commands bitmap		*/
#define S_CMD_Q_PGMNAME		0x03	/* Query programmer name			*/
#define S_CMD_Q_SERBUF		0x04	/* Query Serial Buffer Size			*/
#define S_CMD_Q_BUSTYPE		0x05	/* Query supported bustypes			*/
#define S_CMD_Q_CHIPSIZE	0x06	/* Query supported chipsize (2^n format)	*/
#define S_CMD_Q_OPBUF		0x07	/* Query operation buffer size			*/
#define S_CMD_Q_WRNMAXLEN	0x08	/* Query Write to opbuf: Write-N maximum length */
#define S_CMD_R_BYTE		0x09	/* Read a single byte				*/
#define S_CMD_R_NBYTES		0x0A	/* Read n bytes					*/
#define S_CMD_O_INIT		0x0B	/* Initialize operation buffer			*/
#define S_CMD_O_WRITEB		0x0C	/* Write opbuf: Write byte with address		*/
#define S_CMD_O_WRITEN		0x0D	/* Write to opbuf: Write-N			*/
#define S_CMD_O_DELAY		0x0E	/* Write opbuf: udelay				*/
#define S_CMD_O_EXEC		0x0F	/* Execute operation buffer			*/
#define S_CMD_SYNCNOP		0x10	/* Special no-operation that returns NAK+ACK	*/
#define S_CMD_Q_RDNMAXLEN	0x11	/* Query read-n maximum length			*/
#define S_CMD_S_BUSTYPE		0x12	/* Set used bustype(s).				*/
#define S_CMD_O_SPIOP		0x13	/* Perform SPI operation.			*/
#define S_CMD_S_SPI_FREQ	0x14	/* Set SPI clock frequency			*/
#define S_CMD_S_PIN_STATE	0x15	/* Enable/disable output drivers		*/

#define GLITCH_PIN 15
#define PIN_MISO PICO_DEFAULT_SPI_RX_PIN
#define PIN_MOSI PICO_DEFAULT_SPI_TX_PIN
#define PIN_SCK PICO_DEFAULT_SPI_SCK_PIN
#define PIN_CS PICO_DEFAULT_SPI_CSN_PIN
#define BUS_SPI         (1 << 3)
#define S_SUPPORTED_BUS   BUS_SPI
#define S_CMD_MAP ( \
  (1 << S_CMD_NOP)       | \
  (1 << S_CMD_Q_IFACE)   | \
  (1 << S_CMD_Q_CMDMAP)  | \
  (1 << S_CMD_Q_PGMNAME) | \
  (1 << S_CMD_Q_SERBUF)  | \
  (1 << S_CMD_Q_BUSTYPE) | \
  (1 << S_CMD_SYNCNOP)   | \
  (1 << S_CMD_O_SPIOP)   | \
  (1 << S_CMD_S_BUSTYPE) | \
  (1 << S_CMD_S_SPI_FREQ)| \
  (1 << S_CMD_S_PIN_STATE) \
)

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

uint32_t getu24() {
    uint32_t c1 = getchar();
    uint32_t c2 = getchar();
    uint32_t c3 = getchar();
    return c1 | (c2<<8) | (c3<<16);
}

uint32_t getu32() {
    uint32_t c1 = getchar();
    uint32_t c2 = getchar();
    uint32_t c3 = getchar();
    uint32_t c4 = getchar();
    return c1 | (c2<<8) | (c3<<16) | (c4<<24);
}

void putu32(uint32_t d) {
    char buf[4];
    memcpy(buf, &d, 4);
    putchar(buf[0]);
    putchar(buf[1]);
    putchar(buf[2]);
    putchar(buf[3]);
}

void read_from_spi(spi_inst_t * spi, const size_t rlen) {
    uint32_t chunk;
    char buf[64];

    for(uint32_t i = 0; i < rlen; i += chunk) {
        chunk = MIN(rlen - i, sizeof(buf));
        spi_read_blocking(spi, 0, buf, chunk);
        fwrite(buf, 1, chunk, stdout);
        fflush(stdout);
    }
}

unsigned char write_buffer[512];

void process(spi_inst_t * spi, int command) {
    switch(command) {
        case S_CMD_NOP:
            putchar(S_ACK);
            break;
        case S_CMD_Q_IFACE:
            putchar(S_ACK);
            putchar(0x01);
            putchar(0x00);
            break;
        case S_CMD_Q_CMDMAP:
            putchar(S_ACK);
            putu32(S_CMD_MAP);

            for(int i = 0; i < 32 - sizeof(uint32_t); i++) {
                putchar(0);
            }
            break;
        case S_CMD_Q_PGMNAME:
            putchar(S_ACK);
            fwrite("pico-serprog\x0\x0\x0\x0\x0", 1, 16, stdout);
            fflush(stdout);
            break;
        case S_CMD_Q_SERBUF:
            putchar(S_ACK);
            putchar(0xFF);
            putchar(0xFF);
            break;
        case S_CMD_Q_BUSTYPE:
            putchar(S_ACK);
            putchar(S_SUPPORTED_BUS);
            break;
        case S_CMD_SYNCNOP:
            putchar(S_NAK);
            putchar(S_ACK);
            break;
        case S_CMD_S_BUSTYPE:
            {
                int bustype = getchar();
                if((bustype | S_SUPPORTED_BUS) == S_SUPPORTED_BUS) {
                    putchar(S_ACK);
                } else {
                    putchar(S_NAK);
                }
            }
            break;
        case S_CMD_O_SPIOP:
            {
                uint32_t wlen = getu24();
                uint32_t rlen = getu24();

                cs_select(PIN_CS);
                fread(write_buffer, 1, wlen, stdin);
                spi_write_blocking(spi, write_buffer, wlen);

                putchar(S_ACK);
                read_from_spi(spi, rlen);
                cs_deselect(PIN_CS);
            }
            break;
        case S_CMD_S_SPI_FREQ:
            {
                uint32_t freq = getu32();
                if (freq >= 1) {
                    putchar(S_ACK);
                    putu32(spi_set_baudrate(spi, freq));
                } else {
                    putchar(S_NAK);
                }
            }
            break;
        case S_CMD_S_PIN_STATE:
            //TODO:
            getchar();
            putchar(S_ACK);
            break;
        case 0x66: // custom command to insert a voltage glitch
            {
                uint32_t wlen = getu24();
                uint32_t rlen = getu24();
                uint32_t glitch_cycles = getu32();

                fread(write_buffer, 1, wlen, stdin);
                putchar(S_ACK);

                multicore_fifo_push_blocking(glitch_cycles);
                // Synchronize with core1
                multicore_fifo_pop_blocking();

                cs_select(PIN_CS);
                spi_write_blocking(spi, write_buffer, wlen);
                read_from_spi(spi, rlen);
                cs_deselect(PIN_CS);

                // Synchronize with core1 to ensure the glitch doesn't happen at a later point
                multicore_fifo_pop_blocking();
            }
            break;
        default:
            putchar(S_NAK);
    }
}

void __time_critical_func(core1_glitch_pulldown_loop)(void)
{
    while (true) {
        uint32_t glitch_cycles = multicore_fifo_pop_blocking();
        // Synchronize with core0
        multicore_fifo_push_blocking(0);

        while (glitch_cycles-- > 0)
            ;
        
        gpio_put(GLITCH_PIN, 1);
        // Add some delay to have our gate driver actually recognize the signal
        asm volatile("nop\nnop\nnop\nnop\nnop\nnop");
        gpio_put(GLITCH_PIN, 0);

        // Synchronize with core0
        multicore_fifo_push_blocking(0);
    }
}

int main() {
    // Metadata for picotool
    bi_decl(bi_program_description("Flashrom/serprog compatible firmware for the Raspberry Pi Pico W.\n"
                                   "Extended to allow for the transmission of glitch cycles"));
    bi_decl(bi_program_url("https://github.com/EratesXD/RPMC_glitch_setup"));
    bi_decl(bi_1pin_with_name(PIN_MISO, "MISO"));
    bi_decl(bi_1pin_with_name(PIN_MOSI, "MOSI"));
    bi_decl(bi_1pin_with_name(PIN_SCK, "SCK"));
    bi_decl(bi_1pin_with_name(PIN_CS, "CS"));

    stdio_init_all();

    stdio_set_translate_crlf(&stdio_usb, false);

    spi_init(spi0, 1000 * 1000);
    gpio_set_function(PIN_MISO, GPIO_FUNC_SPI);
    gpio_set_function(PIN_SCK, GPIO_FUNC_SPI);
    gpio_set_function(PIN_MOSI, GPIO_FUNC_SPI);
    // Make the SPI pins available to picotool
    bi_decl(bi_3pins_with_func(PIN_MISO, PIN_SCK, PIN_MOSI, GPIO_FUNC_SPI));

    // Glitch pin shorts the voltage of the chip to ground when it is set high
    gpio_init(GLITCH_PIN);
    gpio_put(GLITCH_PIN, 0);
    gpio_set_dir(GLITCH_PIN, GPIO_OUT);
    bi_decl(bi_1pin_with_name(GLITCH_PIN, "GLITCH PIN"));

    // Setup second core to pull the glitch pin down after a recieved countdown
    multicore_reset_core1();
    multicore_launch_core1(core1_glitch_pulldown_loop);

    // Initialize CS
    gpio_init(PIN_CS);
    gpio_put(PIN_CS, 1);
    gpio_set_dir(PIN_CS, GPIO_OUT);

    // Command handling
    while(true) {
        int command = getchar();
        process(spi0, command);
    }

    spi_deinit(spi0);

    return 0;
}
