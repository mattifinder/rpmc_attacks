// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Matti Finder
// Copyright (c) 2026 Julian Prein

#include <pico/stdlib.h>
#include <pico/binary_info.h>
#include <pico/multicore.h>
#include <hardware/spi.h>
#include <mbedtls/md.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "amd_trigger.pio.h"
#include "psp_nvdata.h"
#include "flash.h"


#define PIN_N_MUX_EN 16
bi_decl(bi_1pin_with_name(PIN_N_MUX_EN, "#MUX enable"));
#define PIN_MUX_INTERPOSE 18

#define PIN_N_LLS_OE 17

#define PIN_LLS_1DIR 22
#define PIN_LLS_2DIR 19

#define CAPTURE_SPI spi0
#define MASTER_SPI CAPTURE_SPI
#define PIN_CHIP_SPI_CLK 2
#define PIN_CHIP_MASTER_SPI_RX 3
#define PIN_CHIP_MASTER_SPI_TX 4
#define PIN_CHIP_SPI_CS 5

#define OUTPUT_SPI spi1
#define PIN_PICO_BOARD_SPI_CLK 10
#define PIN_PICO_BOARD_SPI_TX 11
#define PIN_PICO_BOARD_SPI_RX 12
#define PIN_PICO_BOARD_SPI_CS 13


inline uint32_t reverse(const uint32_t x)
{
    return ((x & UINT32_C(0x0000'00FF)) << 24) |
           ((x & UINT32_C(0x0000'FF00)) <<  8) |
           ((x & UINT32_C(0x00FF'0000)) >>  8) |
           ((x & UINT32_C(0xFF00'0000)) >> 24); 
}

static inline void interpose_no_push()
{
    gpio_set_mask((1 << PIN_MUX_INTERPOSE) | (1 << PIN_LLS_1DIR));
}

static inline void interpose()
{
    interpose_no_push();
    multicore_fifo_push_blocking(132);
}

static inline void stop_interpose()
{
    gpio_clr_mask((1 << PIN_MUX_INTERPOSE) | (1 << PIN_LLS_1DIR));
}

void __time_critical_func(rpmc_interpose_increment_core1)(void)
{
    const static uint8_t status[] = {0xff, // to finish the rpmc transmission
                                     0xff, 0x00,
                                     0xff, 0x00,
                                     0xff, 0xff, 0x80,
                                     0xff, 0x00};
    const static size_t status_length[] = {1, 2, 2, 3, 2};
    while (true) {
        multicore_fifo_pop_blocking();

        const uint8_t * status_pos = status;
        
        for (size_t counter = 0; counter < count_of(status_length); counter++) {
            spi_write_blocking(OUTPUT_SPI, status_pos, status_length[counter]);
            status_pos += status_length[counter];
        }

        stop_interpose();
    }
}

void reprogram_flash(spi_inst_t * const out_spi, const unsigned int cs)
{
    write_segment(out_spi, cs, 0x10e0000, sizeof(psp_nvdata_bin), psp_nvdata_bin);
    write_segment(out_spi, cs, 0x1100000, sizeof(psp_nvram_bin), psp_nvram_bin);
    write_segment(out_spi, cs, 0x1060000, sizeof(nvrom_state_bin), nvrom_state_bin);

    for (uint32_t start = 0x01102000; start  < 0x1100000 + 0x40000; start += FLASH_SECTOR_SIZE) {
        flash_write_enable(out_spi, cs);
        sleep_us(100);
        flash_erase(out_spi, cs, start);
        sleep_us(100);
        flash_wait_done(out_spi, cs);
        printf("flash_erase: %x\n", start);
    }
}

void init_mux()
{
    gpio_init(PIN_N_MUX_EN);
    gpio_put(PIN_N_MUX_EN, 0); // mux is active low
    gpio_set_dir(PIN_N_MUX_EN, GPIO_OUT);

    gpio_init(PIN_MUX_INTERPOSE);
    gpio_put(PIN_MUX_INTERPOSE, 0);
    gpio_set_dir(PIN_MUX_INTERPOSE, GPIO_OUT);
    gpio_set_slew_rate(PIN_MUX_INTERPOSE, GPIO_SLEW_RATE_FAST);
}

void init_lls(const bool lls1_dir, const bool lss2_dir)
{
    gpio_init(PIN_N_LLS_OE);
    gpio_put(PIN_N_LLS_OE, 0);
    gpio_set_dir(PIN_N_LLS_OE, GPIO_OUT);

    gpio_init(PIN_LLS_1DIR);
    gpio_put(PIN_LLS_1DIR, lls1_dir);
    gpio_set_dir(PIN_LLS_1DIR, GPIO_OUT);
    gpio_set_slew_rate(PIN_LLS_1DIR, GPIO_SLEW_RATE_FAST);

    gpio_init(PIN_LLS_2DIR);
    gpio_put(PIN_LLS_2DIR, lss2_dir);
    gpio_set_dir(PIN_LLS_2DIR, GPIO_OUT);
}

void init_spi0_master()
{
    spi_init(CAPTURE_SPI, 1 * 1000 * 1000);

    gpio_init(PIN_CHIP_SPI_CS);
    gpio_put(PIN_CHIP_SPI_CS, 1);
    gpio_set_dir(PIN_CHIP_SPI_CS, GPIO_OUT);

    gpio_set_function(PIN_CHIP_SPI_CLK, GPIO_FUNC_SPI);
    gpio_set_function(PIN_CHIP_MASTER_SPI_RX , GPIO_FUNC_SPI);
    gpio_set_function(PIN_CHIP_MASTER_SPI_TX , GPIO_FUNC_SPI);
}

void init_spi1_interposer()
{
    spi_init(OUTPUT_SPI, 25 * 1000 * 1000);
    spi_set_slave(OUTPUT_SPI, true);
    // The spi set format function seems not work as specified in the documentation
    spi_set_format(OUTPUT_SPI, 8, SPI_MSB_FIRST, SPI_CPHA_1, 1);

    gpio_set_function(PIN_PICO_BOARD_SPI_CLK, GPIO_FUNC_SPI);
    gpio_set_function(PIN_PICO_BOARD_SPI_CS, GPIO_FUNC_SPI);
    gpio_set_function(PIN_PICO_BOARD_SPI_TX, GPIO_FUNC_SPI);
    gpio_set_function(PIN_PICO_BOARD_SPI_RX, GPIO_FUNC_SPI);
}

int main()
{
    stdio_init_all();

    switch (getchar()) {
        // interpose amd 
        case 'a':
            init_mux();
            init_lls(0, 0);
            // initlialize spi trigger
            amd_trigger_init(PIN_CHIP_SPI_CS, PIN_CHIP_SPI_CLK, PIN_CHIP_MASTER_SPI_RX);
            init_spi1_interposer();
            printf("Interposing AMD\n");

            multicore_launch_core1(rpmc_interpose_increment_core1);
            amd_trigger(interpose);
            break;
        case 'r':
            init_lls(1, 0);
            init_spi0_master();
            
            printf("Reprogramming flash sector\n");
            reprogram_flash(MASTER_SPI, PIN_CHIP_SPI_CS);
            break;
        default: // do nothing just leave chip directly connected
            init_mux();
            printf("Just passing traffic through\n");
            break;
    }

    while (true)
        tight_loop_contents();

    return 0;
}