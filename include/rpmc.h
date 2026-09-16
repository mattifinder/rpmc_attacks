#ifndef RPMC_H
#define RPMC_H

#include <stdint.h>
#include <stdio.h>

#define RPMC_OP1 0x9B
#define RPMC_OP2 0x96

#define RPMC_REQUEST ((RPMC_OP1 << 8) | 0x03)
#define RPMC_INCREMENT ((RPMC_OP1 << 8) | 0x02)

enum rpmc_status_short : uint8_t {
	WAIT = 0x01,
	DONE = 0x80,
};

union rpmc_request {
	struct __attribute((__packed__)) {
		uint8_t op1;
		uint8_t typ;
		uint8_t idx;
		uint8_t reserved;
		uint8_t tag[12];
		// we don't need the signature and this way everything fits
		// nicely into the FIFO at once
		//uint8_t sig[32];
	};

	uint32_t words[4]; // 12 with sig
	uint8_t buf[16]; // 48 with sig
};

union rpmc_read_data {
	struct __attribute((__packed__)) {
		enum rpmc_status_short status;
		uint8_t tag[12];
		uint32_t val;
		uint8_t sig[32];
	};

	uint32_t words[13]; // last word is not used fully
	uint8_t buf[49];
};

union rpmc_increment {
	struct __attribute((__packed__)) {
		uint8_t op1;
		uint8_t typ;
		uint8_t idx;
		uint8_t reserved;
		uint32_t old;
		// we don't need the signature and this way everything fits
		// nicely into the FIFO at once
		//uint8_t sig[32];
	};

	uint32_t words[2]; // 10 with sig
	uint8_t buf[8]; // 40 with sig
};

static inline void print_rpmc_request(union rpmc_request req)
{
	printf("request:\n"
	       "\tidx: %02x\n"
	       "\ttag: %02x%02x...%02x%02x\n",
	       req.idx, req.tag[0], req.tag[1], req.tag[10], req.tag[11]);
}

static inline void print_rpmc_read_data(union rpmc_read_data status)
{
	printf("status:\n"
	       "\ttag: %02x%02x...%02x%02x\n"
	       "\tval: %08x\n"
	       "\tsig: %02x%02x...%02x%02x\n",
	       status.tag[0], status.tag[1], status.tag[10], status.tag[11],
	       status.val, status.sig[0], status.sig[1], status.sig[30],
	       status.sig[31]);
}

static inline void print_rpmc_increment(union rpmc_increment inc)
{
#if 0
    printf("increment:\n"
           "\tidx: %02x\n"
           "\told: %08x\n",
           inc.idx, inc.old);
#else
	printf("++c%d (=%x)\n", inc.idx, inc.old + 1);
#endif
}

#endif // RPMC_H
