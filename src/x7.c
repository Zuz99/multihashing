#include "x7.h"
#include <sph_blake.h>
#include <sph_bmw.h>
#include <sph_groestl.h>
#include <sph_skein.h>
#include <sph_keccak.h>
#include <sph_luffa.h>
#include <sph_echo.h>
#include <string.h>

static void hash_blake512(const unsigned char *data, unsigned char *hash) {
    sph_blake512_context ctx;
    sph_blake512_init(&ctx);
    sph_blake512(&ctx, data, (data ? 64 : 0));
    sph_blake512_close(&ctx, hash);
}

static void hash_bmw512(const unsigned char *data, unsigned char *hash) {
    sph_bmw512_context ctx;
    sph_bmw512_init(&ctx);
    sph_bmw512(&ctx, data, 64);
    sph_bmw512_close(&ctx, hash);
}

static void hash_groestl512(const unsigned char *data, unsigned char *hash) {
    sph_groestl512_context ctx;
    sph_groestl512_init(&ctx);
    sph_groestl512(&ctx, data, 64);
    sph_groestl512_close(&ctx, hash);
}

static void hash_skein512(const unsigned char *data, unsigned char *hash) {
    sph_skein512_context ctx;
    sph_skein512_init(&ctx);
    sph_skein512(&ctx, data, 64);
    sph_skein512_close(&ctx, hash);
}

static void hash_keccak512(const unsigned char *data, unsigned char *hash) {
    sph_keccak512_context ctx;
    sph_keccak512_init(&ctx);
    sph_keccak512(&ctx, data, 64);
    sph_keccak512_close(&ctx, hash);
}

static void hash_luffa512(const unsigned char *data, unsigned char *hash) {
    sph_luffa512_context ctx;
    sph_luffa512_init(&ctx);
    sph_luffa512(&ctx, data, 64);
    sph_luffa512_close(&ctx, hash);
}

static void hash_echo512(const unsigned char *data, unsigned char *hash) {
    sph_echo512_context ctx;
    sph_echo512_init(&ctx);
    sph_echo512(&ctx, data, 64);
    sph_echo512_close(&ctx, hash);
}

uint256 HashX7(const unsigned char *pbegin, const unsigned char *pend, uint64_t timestamp) {
    uint512 hash[7];
    unsigned char temp1[64];
    unsigned char temp2[64];
    static unsigned char pblank[1] = {0};

    // Incorporate the timestamp into the initial data
    hash_blake512((unsigned char *)&timestamp, (unsigned char *)&hash[0]);
    hash_blake512((pbegin == pend ? pblank : pbegin), (unsigned char *)&hash[0]);

    hash_bmw512((unsigned char *)&hash[0], (unsigned char *)&hash[1]);

    // Add XOR operation between stages for sophistication
    memcpy(temp1, &hash[0], 64);
    memcpy(temp2, &hash[1], 64);
    for (int i = 0; i < 64; ++i) {
        temp2[i] ^= temp1[i];
    }
    memcpy(&hash[1], temp2, 64);

    hash_groestl512((unsigned char *)&hash[1], (unsigned char *)&hash[2]);

    hash_skein512((unsigned char *)&hash[2], (unsigned char *)&hash[3]);

    // Another XOR operation for sophistication
    memcpy(temp1, &hash[2], 64);
    memcpy(temp2, &hash[3], 64);
    for (int i = 0; i < 64; ++i) {
        temp2[i] ^= temp1[i];
    }
    memcpy(&hash[3], temp2, 64);

    hash_keccak512((unsigned char *)&hash[3], (unsigned char *)&hash[4]);

    hash_luffa512((unsigned char *)&hash[4], (unsigned char *)&hash[5]);

    hash_echo512((unsigned char *)&hash[5], (unsigned char *)&hash[6]);

    // Final XOR operation for sophistication
    memcpy(temp1, &hash[5], 64);
    memcpy(temp2, &hash[6], 64);
    for (int i = 0; i < 64; ++i) {
        temp2[i] ^= temp1[i];
    }
    memcpy(&hash[6], temp2, 64);

    uint256 final_hash;
    memcpy(final_hash.data, hash[6].data, sizeof(final_hash.data));
    return final_hash;
}
void x7_hash(const char* input, char* output, uint32_t len)
{
    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_skein512_context     ctx_skein;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_luffa512_context	ctx_luffa1;
    sph_cubehash512_context	ctx_cubehash1;
    sph_shavite512_context	ctx_shavite1;
    sph_simd512_context		ctx_simd1;
    sph_echo512_context		ctx_echo1;
    sph_hamsi512_context	ctx_hamsi1;
    sph_fugue512_context	ctx_fugue1;
    sph_shabal512_context       ctx_shabal1;
    sph_whirlpool_context       ctx_whirlpool1;

    //these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t hashA[16], hashB[16];

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, len);
    sph_blake512_close (&ctx_blake, hashA);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hashA, 64);
    sph_bmw512_close(&ctx_bmw, hashB);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashB, 64);
    sph_groestl512_close(&ctx_groestl, hashA);

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, hashA, 64);
    sph_skein512_close (&ctx_skein, hashB);

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hashB, 64);
    sph_jh512_close(&ctx_jh, hashA);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hashA, 64);
    sph_keccak512_close(&ctx_keccak, hashB);

    sph_luffa512_init (&ctx_luffa1);
    sph_luffa512 (&ctx_luffa1, hashB, 64);
    sph_luffa512_close (&ctx_luffa1, hashA);

    sph_cubehash512_init (&ctx_cubehash1);
    sph_cubehash512 (&ctx_cubehash1, hashA, 64);
    sph_cubehash512_close(&ctx_cubehash1, hashB);

    sph_shavite512_init (&ctx_shavite1);
    sph_shavite512 (&ctx_shavite1, hashB, 64);
    sph_shavite512_close(&ctx_shavite1, hashA);

    sph_simd512_init (&ctx_simd1);
    sph_simd512 (&ctx_simd1, hashA, 64);
    sph_simd512_close(&ctx_simd1, hashB);

    sph_echo512_init (&ctx_echo1);
    sph_echo512 (&ctx_echo1, hashB, 64);
    sph_echo512_close(&ctx_echo1, hashA);

    sph_hamsi512_init (&ctx_hamsi1);
    sph_hamsi512 (&ctx_hamsi1, hashA, 64);
    sph_hamsi512_close(&ctx_hamsi1, hashB);

    sph_fugue512_init (&ctx_fugue1);
    sph_fugue512 (&ctx_fugue1, hashB, 64);
    sph_fugue512_close(&ctx_fugue1, hashA);

    sph_shabal512_init (&ctx_shabal1);
    sph_shabal512 (&ctx_shabal1, hashA, 64);
    sph_shabal512_close(&ctx_shabal1, hashB);

    sph_whirlpool_init (&ctx_whirlpool1);
    sph_whirlpool (&ctx_whirlpool1, hashB, 64);
    sph_whirlpool_close(&ctx_whirlpool1, hashA);

    memcpy(output, hashA, 32);

}