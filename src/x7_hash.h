#ifndef X7_HASH_H
#define X7_HASH_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    unsigned char data[64];
} uint512;

typedef struct {
    unsigned char data[32];
} uint256;

uint256 HashX7(const unsigned char *pbegin, const unsigned char *pend, uint64_t timestamp);

#endif // X7_HASH_H
