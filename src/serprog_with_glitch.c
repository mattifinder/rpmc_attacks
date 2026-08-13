/**
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

#define GLITCH_PIN 17
#define PIN_MISO 4
#define PIN_MOSI 3
#define PIN_SCK 2
#define PIN_CS 5
#define PIN_1V8_OE 21
#define PIN_DIR_A 22
#define PIN_DIR_B 20
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

unsigned char write_buffer[1024];

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
                // As of now you can't write commands larger than write_buffer
                if (wlen > sizeof(write_buffer)) {
                    wlen = sizeof(write_buffer);
                }

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

inline static void __attribute((always_inline)) __time_critical_func(wait_delay)(const size_t delay)
{
    switch (delay)
    {
        case 30:
            asm volatile("nop");
        case 29:
            asm volatile("nop");
        case 28:
            asm volatile("nop");
        case 27:
            asm volatile("nop");
        case 26:
            asm volatile("nop");
        case 25:
            asm volatile("nop");
        case 24:
            asm volatile("nop");
        case 23:
            asm volatile("nop");
        case 22:
            asm volatile("nop");  
        case 21:
            asm volatile("nop");
        case 20:
            asm volatile("nop");
        case 19:
            asm volatile("nop");
        case 18:
            asm volatile("nop");
        case 17:
            asm volatile("nop");
        case 16:
            asm volatile("nop");
        case 15:
            asm volatile("nop");
        case 14:
            asm volatile("nop");
        case 13:
            asm volatile("nop");
        case 12:
            asm volatile("nop");  
        case 11:
            asm volatile("nop");
        case 10:
            asm volatile("nop");
        case 9:
            asm volatile("nop");
        case 8:
            asm volatile("nop");
        case 7:
            asm volatile("nop");
        case 6:
            asm volatile("nop");
        case 5:
            asm volatile("nop");
        case 4:
            asm volatile("nop");
        case 3:
            asm volatile("nop");
        case 2:
            asm volatile("nop");
        case 1:
            asm volatile("nop");
        default:
            asm volatile("nop");
    }
}

void __time_critical_func(core1_glitch_pulldown_loop)(void)
{
    volatile size_t delay = 21;
    while (true) {
        volatile uint32_t glitch_cycles = multicore_fifo_pop_blocking();
        // Synchronize with core0
        multicore_fifo_push_blocking(0);

        while (glitch_cycles-- > 0)
            ;
        
        gpio_put(GLITCH_PIN, 1);
        // Add some delay to have our gate driver actually recognize the signal
        wait_delay(delay);
        gpio_put(GLITCH_PIN, 0);

        // Synchronize with core0
        multicore_fifo_push_blocking(0);
    }
}

void __time_critical_func(brute_force_delay)(void)
{
    while (true) {
        for (volatile size_t delay = 20; delay < 30; delay += 1){
            volatile uint32_t glitch_cycles = multicore_fifo_pop_blocking();
            // Synchronize with core0
            multicore_fifo_push_blocking(0);

            while (glitch_cycles-- > 0)
                ;
            
            gpio_put(GLITCH_PIN, 1);
            // Add some delay to have our gate driver actually recognize the signal
            wait_delay(delay);
            gpio_put(GLITCH_PIN, 0);

            // Synchronize with core0
            multicore_fifo_push_blocking(0);
        }
    }
}

int main() {
    // Metadata for picotool
    bi_decl(bi_program_description("Flashrom/serprog compatible firmware for the Raspberry Pi Pico W.\n"
                                   "Extended to allow for the transmission of glitch cycles"));
    bi_decl(bi_program_url("https://github.com/EratesXD/RPMC_glitch_setup"));
    bi_decl(bi_1pin_with_name(PIN_CS, "CS"));
    bi_decl(bi_1pin_with_name(GLITCH_PIN, "GLITCH PIN"));
    bi_decl(bi_3pins_with_func(PIN_MISO, PIN_SCK, PIN_MOSI, GPIO_FUNC_SPI));
    bi_decl(bi_3pins_with_names(PIN_DIR_A, "Upper bank pins at logic level shifter", PIN_DIR_B, "lower bank pins at logic level shifter", PIN_1V8_OE, "logic level shifter output enable"));

    stdio_init_all();
    stdio_set_translate_crlf(&stdio_usb, false);

    spi_init(spi0, 1000 * 1000);
    gpio_set_function(PIN_MISO, GPIO_FUNC_SPI);
    gpio_set_function(PIN_SCK, GPIO_FUNC_SPI);
    gpio_set_function(PIN_MOSI, GPIO_FUNC_SPI);

    // Glitch pin shorts the voltage of the chip to ground when it is set high
    gpio_init(GLITCH_PIN);
    gpio_put(GLITCH_PIN, 0);
    gpio_set_slew_rate(GLITCH_PIN, GPIO_SLEW_RATE_FAST);
    gpio_set_dir(GLITCH_PIN, GPIO_OUT);

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

    // configure 1V8 output manually is active low
    gpio_init(PIN_1V8_OE);
    gpio_pull_up(PIN_1V8_OE);

    // Setup second core to pull the glitch pin down after a recieved countdown
    multicore_reset_core1();
#ifdef PROGRAM_MODE_FIXED_DELAY
    multicore_launch_core1(core1_glitch_pulldown_loop);
#elifdef PROGRAM_MODE_FIND_DELAY
    multicore_launch_core1(brute_force_delay);
#else
    #error "No valid program mode defined"
#endif

    // Command handling
    while(true) {
        int command = getchar();
        process(spi0, command);
    }

    spi_deinit(spi0);

    return 0;
}
