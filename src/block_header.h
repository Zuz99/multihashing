#ifndef BLOCK_HEADER_H
#define BLOCK_HEADER_H

#include <stdint.h>
#include <stddef.h>
#include "x7_hash.h"

// Define the block header structure
typedef struct {
    uint32_t nVersion;
    unsigned char hashPrevBlock[32];
    unsigned char hashMerkleRoot[32];
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
} CBlockHeader;

// Function prototypes
uint256 GetBlockHash(const CBlockHeader *header);

#endif // BLOCK_HEADER_H
