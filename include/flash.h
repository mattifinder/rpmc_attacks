#ifndef FLASH_H
#define FLASH_H

#include <pico/stdlib.h>
#include <hardware/spi.h>

#define FLASH_PAGE_SIZE 256
#define FLASH_SECTOR_SIZE 4096

void flash_write_enable(spi_inst_t *spi, uint cs_pin);
void flash_erase(spi_inst_t *spi, uint cs_pin, uint32_t addr);
void flash_wait_done(spi_inst_t *spi, uint cs_pin);
void write_segment(spi_inst_t *const out_spi, const unsigned int cs,
                   const uint32_t base_addres, const size_t len,
                   const uint8_t data[len]);

#endif // FLASH_H
