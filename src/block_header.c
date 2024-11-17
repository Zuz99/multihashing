#include "block_header.h"
#include <string.h>
#include <stdio.h>

// Dummy implementation of GetBlockTime() - replace with actual implementation
uint32_t GetBlockTime() {
    return 0; // Placeholder value
}

// Serialize block header into a buffer
static void SerializeBlockHeader(const CBlockHeader *header, unsigned char *buffer) {
    memcpy(buffer, &header->nVersion, sizeof(header->nVersion));
    memcpy(buffer + sizeof(header->nVersion), header->hashPrevBlock, sizeof(header->hashPrevBlock));
    memcpy(buffer + sizeof(header->nVersion) + sizeof(header->hashPrevBlock), header->hashMerkleRoot, sizeof(header->hashMerkleRoot));
    memcpy(buffer + sizeof(header->nVersion) + sizeof(header->hashPrevBlock) + sizeof(header->hashMerkleRoot), &header->nTime, sizeof(header->nTime));
    memcpy(buffer + sizeof(header->nVersion) + sizeof(header->hashPrevBlock) + sizeof(header->hashMerkleRoot) + sizeof(header->nTime), &header->nBits, sizeof(header->nBits));
    memcpy(buffer + sizeof(header->nVersion) + sizeof(header->hashPrevBlock) + sizeof(header->hashMerkleRoot) + sizeof(header->nTime) + sizeof(header->nBits), &header->nNonce, sizeof(header->nNonce));
}

uint256 GetBlockHash(const CBlockHeader *header) {
    unsigned char buffer[80]; // 80 bytes for the block header
    SerializeBlockHeader(header, buffer);

    uint32_t prevTimestamp = GetBlockTime();
    uint256 hash = HashX7(buffer, buffer + sizeof(buffer), prevTimestamp);

    return hash;
}
