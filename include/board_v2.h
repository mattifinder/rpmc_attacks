#ifndef BOARD_V2_H
#define BOARD_V2_H

#include <pico/binary_info.h>

#define PIN_MUX_ENABLE 17
/* During development and debugging of issues with the mux we physically shorted
 * the enable pin on some of our boards, since we don't really need to configure
 * it and wanted to eliminate it as the problem source.
 */
#undef PIN_MUX_ENABLE
#ifdef PIN_MUX_ENABLE
bi_decl(bi_1pin_with_name(PIN_MUX_ENABLE, "#MUX enable"));
#endif

#define PIN_MUX_INTERPOSE 16
bi_decl(bi_1pin_with_name(PIN_MUX_INTERPOSE,
                          "MUX switch (0 is chip, 1 is pico)"));

#define PIN_CHIP_VOLT_SEL 23
#define PIN_CHIP_VOLT_MODE 24

// through multiplexer
#define PIN_PICO_OUT_SPI_MOSI_DQ0 12
#define PIN_PICO_OUT_SPI_SCK 13
#define PIN_PICO_OUT_SPI_DQ2 14
#define PIN_PICO_OUT_SPI_CS 15
#define PIN_PICO_OUT_SPI_DQ3 21
#define PIN_PICO_OUT_SPI_MISO_DQ1 22

// directly connected
#define PIN_PICO_BOARD_SPI_MOSI_DQ0 1
#define PIN_PICO_BOARD_SPI_CLK 2
#define PIN_PICO_BOARD_SPI_HOLD_DQ3 3
#define PIN_PICO_BOARD_SPI_WP_DQ2 4
#define PIN_PICO_BOARD_SPI_MISO_DQ1 5
#define PIN_PICO_BOARD_SPI_CS 6

// pins to reprogram the flash
#define MASTER_SPI CAPTURE_SPI
#define PIN_PICO_CHIP_SPI_RX 32
#define PIN_PICO_CHIP_SPI_CS 33
#define PIN_PICO_CHIP_SPI_CLK 34
#define PIN_PICO_CHIP_SPI_TX 35
#define PICO_CHIP_SPI_INST spi0

enum mux_dir {
	MUX_TARGET_CHIP,
	MUX_TARGET_PICO,
};

#endif /* BOARD_V2_H */
