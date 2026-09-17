#include <pico/stdlib.h>
#include <hardware/spi.h>
#include "flash.h"

static inline void cs_select(uint cs_pin)
{
	asm volatile("nop \n nop \n nop"); // FIXME
	gpio_put(cs_pin, 0);
	asm volatile("nop \n nop \n nop"); // FIXME
}

static inline void cs_deselect(uint cs_pin)
{
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

void flash_erase(spi_inst_t *spi, uint cs_pin, uint32_t addr)
{
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

void flash_write(spi_inst_t *spi, uint cs_pin, uint32_t addr,
                 const uint8_t *buf, const size_t len)
{
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

void flash_write_enable(spi_inst_t *spi, uint cs_pin)
{
	cs_select(cs_pin);
	const uint8_t cmdbuf[] = {
		0x06, // flash write enable
	};

	spi_write_blocking(spi, cmdbuf, sizeof(cmdbuf));
	cs_deselect(cs_pin);
}

void flash_wait_done(spi_inst_t *spi, uint cs_pin)
{
	while (get_flash_status(spi, cs_pin) != 0)
		sleep_us(100);
}

void write_segment(spi_inst_t *const out_spi, const unsigned int cs,
                   const uint32_t base_addres, const size_t len,
                   const uint8_t data[len])
{
	for (uint32_t offset = 0; offset < len; offset += FLASH_PAGE_SIZE) {
		const uint32_t target_addr = base_addres + offset;

		// Erase
		if (target_addr % FLASH_SECTOR_SIZE == 0) {
			flash_write_enable(out_spi, cs);
			sleep_us(100);
			flash_erase(out_spi, cs, target_addr);
			sleep_us(100);
			flash_wait_done(out_spi, cs);
		}

		// Write
		flash_write_enable(out_spi, cs);
		sleep_us(100);
		flash_write(out_spi, cs, target_addr, data + offset,
		            MIN(len - offset, FLASH_PAGE_SIZE));
		sleep_us(100);
		flash_wait_done(out_spi, cs);
	}
}
