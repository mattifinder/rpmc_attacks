#ifndef RPMC_H
#define RPMC_H

#include <stdint.h>

union rpmc_request {
    struct __attribute((__packed__)) {
        uint8_t op1;
        uint8_t typ;
        uint8_t idx;
        uint8_t reserved;
        uint8_t tag[12];
        // we don't need the signature and this way everything fits nicely into
        // the FIFO at once
        //uint8_t sig[32];
    };
    uint32_t words[4]; // 12 with sig
    uint8_t buf[16];   // 48 with sig
};

union rpmc_read_data {
    struct __attribute((__packed__)) {
        enum : uint8_t {
            WAIT = 0x01,
            DONE = 0x80,
        } status;
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
        // we don't need the signature and this way everything fits nicely into
        // the FIFO at once
        //uint8_t sig[32];
    };
    uint32_t words[2]; // 10 with sig
    uint8_t buf[8];    // 40 with sig
};

#endif // RPMC_H
