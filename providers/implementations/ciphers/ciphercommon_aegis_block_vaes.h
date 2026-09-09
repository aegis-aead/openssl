/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* AEGIS vector of AEGIS_DEGREE AES blocks (an even number), using VAES */

#if !defined(OSSL_PROV_CIPHERCOMMON_AEGIS_BLOCK_VAES_H)
#define OSSL_PROV_CIPHERCOMMON_AEGIS_BLOCK_VAES_H

#include <immintrin.h>

#define AEGIS_VAES_REGS (AEGIS_DEGREE / 2)

typedef struct {
    __m256i b[AEGIS_VAES_REGS];
} aes_block_t;

static ossl_inline aes_block_t AES_BLOCK_XOR(const aes_block_t a,
    const aes_block_t b)
{
    aes_block_t out = { 0 };
    int i;

    for (i = 0; i < AEGIS_VAES_REGS; i++)
        out.b[i] = _mm256_xor_si256(a.b[i], b.b[i]);
    return out;
}

static ossl_inline aes_block_t AES_BLOCK_AND(const aes_block_t a,
    const aes_block_t b)
{
    aes_block_t out = { 0 };
    int i;

    for (i = 0; i < AEGIS_VAES_REGS; i++)
        out.b[i] = _mm256_and_si256(a.b[i], b.b[i]);
    return out;
}

static ossl_inline aes_block_t AES_BLOCK_LOAD(const uint8_t *a)
{
    aes_block_t out = { 0 };
    int i;

    for (i = 0; i < AEGIS_VAES_REGS; i++)
        out.b[i] =
            _mm256_loadu_si256((const __m256i *)(const void *)(a + 32 * i));
    return out;
}

/* Loads the same 16 bytes into every lane */
static ossl_inline aes_block_t AES_BLOCK_LOAD128_BROADCAST(const uint8_t *a)
{
    const __m256i t = _mm256_broadcastsi128_si256(
        _mm_loadu_si128((const __m128i *)(const void *)a));
    aes_block_t out = { 0 };
    int i;

    for (i = 0; i < AEGIS_VAES_REGS; i++)
        out.b[i] = t;
    return out;
}

static ossl_inline aes_block_t AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    const __m256i t = _mm256_broadcastsi128_si256(
        _mm_set_epi64x((long long)a, (long long)b));
    aes_block_t out = { 0 };
    int i;

    for (i = 0; i < AEGIS_VAES_REGS; i++)
        out.b[i] = t;
    return out;
}

static ossl_inline void AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    int i;

    for (i = 0; i < AEGIS_VAES_REGS; i++)
        _mm256_storeu_si256((__m256i *)(void *)(a + 32 * i), b.b[i]);
}

/* Stores all the lanes XORed together, as 16 bytes */
static ossl_inline void AES_BLOCK_FOLD_STORE(uint8_t *a, const aes_block_t b)
{
    __m256i t = b.b[0];
    int i;

    for (i = 1; i < AEGIS_VAES_REGS; i++)
        t = _mm256_xor_si256(t, b.b[i]);
    _mm_storeu_si128((__m128i *)(void *)a,
        _mm_xor_si128(_mm256_castsi256_si128(t),
            _mm256_extracti128_si256(t, 1)));
}

static ossl_inline aes_block_t AES_ENC(const aes_block_t a, const aes_block_t b)
{
    aes_block_t out = { 0 };
    int i;

    for (i = 0; i < AEGIS_VAES_REGS; i++)
        out.b[i] = _mm256_aesenc_epi128(a.b[i], b.b[i]);
    return out;
}

#endif /* !defined(OSSL_PROV_CIPHERCOMMON_AEGIS_BLOCK_VAES_H) */
