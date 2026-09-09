/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* AEGIS vector of AEGIS_DEGREE AES blocks, using the ARMv8 AES instructions */

#if !defined(OSSL_PROV_CIPHERCOMMON_AEGIS_BLOCK_NEON_H)
#define OSSL_PROV_CIPHERCOMMON_AEGIS_BLOCK_NEON_H

/* <arm_neon.h> must be included before the target pragmas */

typedef struct {
    uint8x16_t b[AEGIS_DEGREE];
} aes_block_t;

static ossl_inline aes_block_t AES_BLOCK_XOR(const aes_block_t a,
    const aes_block_t b)
{
    aes_block_t out = { 0 };
    int i;

    for (i = 0; i < AEGIS_DEGREE; i++)
        out.b[i] = veorq_u8(a.b[i], b.b[i]);
    return out;
}

static ossl_inline aes_block_t AES_BLOCK_AND(const aes_block_t a,
    const aes_block_t b)
{
    aes_block_t out = { 0 };
    int i;

    for (i = 0; i < AEGIS_DEGREE; i++)
        out.b[i] = vandq_u8(a.b[i], b.b[i]);
    return out;
}

static ossl_inline aes_block_t AES_BLOCK_LOAD(const uint8_t *a)
{
    aes_block_t out = { 0 };
    int i;

    for (i = 0; i < AEGIS_DEGREE; i++)
        out.b[i] = vld1q_u8(a + 16 * i);
    return out;
}

/* Loads the same 16 bytes into every lane */
static ossl_inline aes_block_t AES_BLOCK_LOAD128_BROADCAST(const uint8_t *a)
{
    const uint8x16_t t = vld1q_u8(a);
    aes_block_t out = { 0 };
    int i;

    for (i = 0; i < AEGIS_DEGREE; i++)
        out.b[i] = t;
    return out;
}

static ossl_inline aes_block_t AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    const uint8x16_t t =
        vreinterpretq_u8_u64(vsetq_lane_u64(a, vmovq_n_u64(b), 1));
    aes_block_t out = { 0 };
    int i;

    for (i = 0; i < AEGIS_DEGREE; i++)
        out.b[i] = t;
    return out;
}

static ossl_inline void AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    int i;

    for (i = 0; i < AEGIS_DEGREE; i++)
        vst1q_u8(a + 16 * i, b.b[i]);
}

/* Stores all the lanes XORed together, as 16 bytes */
static ossl_inline void AES_BLOCK_FOLD_STORE(uint8_t *a, const aes_block_t b)
{
    uint8x16_t t = b.b[0];
    int i;

    for (i = 1; i < AEGIS_DEGREE; i++)
        t = veorq_u8(t, b.b[i]);
    vst1q_u8(a, t);
}

static ossl_inline aes_block_t AES_ENC(const aes_block_t a, const aes_block_t b)
{
    aes_block_t out = { 0 };
    int i;

    for (i = 0; i < AEGIS_DEGREE; i++)
        out.b[i] = veorq_u8(vaesmcq_u8(vaeseq_u8(a.b[i], vmovq_n_u8(0))),
            b.b[i]);
    return out;
}

#endif /* !defined(OSSL_PROV_CIPHERCOMMON_AEGIS_BLOCK_NEON_H) */
