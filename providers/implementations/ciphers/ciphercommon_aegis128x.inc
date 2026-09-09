/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * AEGIS-128X (RFC 10032, section 5.4) with AEGIS_DEGREE lanes.
 * The backend that includes this file defines AEGIS_DEGREE and the
 * aes_block_t vector type.
 */

#define AEGIS_KEYLEN 16
#define AES_BLOCK_LENGTH (16 * AEGIS_DEGREE)
#define RATE (2 * AES_BLOCK_LENGTH)

typedef aes_block_t aegis_state[8];

static void aegis_update(aes_block_t *const state, const aes_block_t d1,
    const aes_block_t d2)
{
    aes_block_t tmp;

    tmp = state[7];
    state[7] = AES_ENC(state[6], state[7]);
    state[6] = AES_ENC(state[5], state[6]);
    state[5] = AES_ENC(state[4], state[5]);
    state[4] = AES_ENC(state[3], state[4]);
    state[3] = AES_ENC(state[2], state[3]);
    state[2] = AES_ENC(state[1], state[2]);
    state[1] = AES_ENC(state[0], state[1]);
    state[0] = AES_ENC(tmp, state[0]);

    state[0] = AES_BLOCK_XOR(state[0], d1);
    state[4] = AES_BLOCK_XOR(state[4], d2);
}

static void aegis_state_init(PROV_AEGIS_CTX *const ctx)
{
    static const uint8_t c0_[] = { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f,
        0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd };
    static const uint8_t c1_[] = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08,
        0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 };
    aegis_state state;
    const aes_block_t c0 = AES_BLOCK_LOAD128_BROADCAST(c0_);
    const aes_block_t c1 = AES_BLOCK_LOAD128_BROADCAST(c1_);
    const aes_block_t k = AES_BLOCK_LOAD128_BROADCAST(ctx->key);
    const aes_block_t n = AES_BLOCK_LOAD128_BROADCAST(ctx->nonce);
    uint8_t context_bytes[AES_BLOCK_LENGTH] = { 0 };
    aes_block_t context;
    int i;

    /* ctx[i] = ZeroPad(Byte(i) || Byte(D - 1), 128) */
    for (i = 0; i < AEGIS_DEGREE; i++) {
        context_bytes[i * 16] = (uint8_t)i;
        context_bytes[i * 16 + 1] = (uint8_t)(AEGIS_DEGREE - 1);
    }
    context = AES_BLOCK_LOAD(context_bytes);

    state[0] = AES_BLOCK_XOR(k, n);
    state[1] = c0;
    state[2] = c1;
    state[3] = c0;
    state[4] = AES_BLOCK_XOR(k, n);
    state[5] = AES_BLOCK_XOR(k, c1);
    state[6] = AES_BLOCK_XOR(k, c0);
    state[7] = AES_BLOCK_XOR(k, c1);

    for (i = 0; i < 10; i++) {
        state[3] = AES_BLOCK_XOR(state[3], context);
        state[7] = AES_BLOCK_XOR(state[7], context);
        aegis_update(state, n, k);
    }

    memcpy(ctx->state, &state, sizeof state);
}

static ossl_inline void aegis_absorb(const uint8_t *const src,
    aes_block_t *const state)
{
    aes_block_t msg0, msg1;

    msg0 = AES_BLOCK_LOAD(src);
    msg1 = AES_BLOCK_LOAD(src + AES_BLOCK_LENGTH);
    aegis_update(state, msg0, msg1);
}

static void aegis_enc(uint8_t *const dst, const uint8_t *const src,
    aes_block_t *const state)
{
    aes_block_t msg0, msg1;
    aes_block_t tmp0, tmp1;

    msg0 = AES_BLOCK_LOAD(src);
    msg1 = AES_BLOCK_LOAD(src + AES_BLOCK_LENGTH);
    tmp0 = AES_BLOCK_XOR(msg0, state[6]);
    tmp0 = AES_BLOCK_XOR(tmp0, state[1]);
    tmp1 = AES_BLOCK_XOR(msg1, state[5]);
    tmp1 = AES_BLOCK_XOR(tmp1, state[2]);
    tmp0 = AES_BLOCK_XOR(tmp0, AES_BLOCK_AND(state[2], state[3]));
    tmp1 = AES_BLOCK_XOR(tmp1, AES_BLOCK_AND(state[6], state[7]));
    AES_BLOCK_STORE(dst, tmp0);
    AES_BLOCK_STORE(dst + AES_BLOCK_LENGTH, tmp1);

    aegis_update(state, msg0, msg1);
}

static void aegis_squeeze_keystream(uint8_t *const dst,
    aes_block_t *const state)
{
    aes_block_t tmp0, tmp1;

    tmp0 = AES_BLOCK_XOR(state[6], state[1]);
    tmp1 = AES_BLOCK_XOR(state[5], state[2]);
    tmp0 = AES_BLOCK_XOR(tmp0, AES_BLOCK_AND(state[2], state[3]));
    tmp1 = AES_BLOCK_XOR(tmp1, AES_BLOCK_AND(state[6], state[7]));
    AES_BLOCK_STORE(dst, tmp0);
    AES_BLOCK_STORE(dst + AES_BLOCK_LENGTH, tmp1);
}

static void aegis_dec(uint8_t *const dst, const uint8_t *const src,
    aes_block_t *const state)
{
    aes_block_t msg0, msg1;

    msg0 = AES_BLOCK_LOAD(src);
    msg1 = AES_BLOCK_LOAD(src + AES_BLOCK_LENGTH);
    msg0 = AES_BLOCK_XOR(msg0, state[6]);
    msg0 = AES_BLOCK_XOR(msg0, state[1]);
    msg1 = AES_BLOCK_XOR(msg1, state[5]);
    msg1 = AES_BLOCK_XOR(msg1, state[2]);
    msg0 = AES_BLOCK_XOR(msg0, AES_BLOCK_AND(state[2], state[3]));
    msg1 = AES_BLOCK_XOR(msg1, AES_BLOCK_AND(state[6], state[7]));
    AES_BLOCK_STORE(dst, msg0);
    AES_BLOCK_STORE(dst + AES_BLOCK_LENGTH, msg1);

    aegis_update(state, msg0, msg1);
}

static void aegis_mac(uint8_t *mac, size_t maclen, uint64_t adlen,
    uint64_t mlen, aes_block_t *const state)
{
    aes_block_t tmp;
    int i;

    tmp = AES_BLOCK_LOAD_64x2(mlen << 3, adlen << 3);
    tmp = AES_BLOCK_XOR(tmp, state[2]);

    for (i = 0; i < 7; i++)
        aegis_update(state, tmp, tmp);
    if (maclen == 16) {
        tmp = AES_BLOCK_XOR(state[6], AES_BLOCK_XOR(state[5], state[4]));
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[3], state[2]));
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[1], state[0]));
        AES_BLOCK_FOLD_STORE(mac, tmp);
    } else if (maclen == 32) {
        tmp = AES_BLOCK_XOR(state[3], state[2]);
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[1], state[0]));
        AES_BLOCK_FOLD_STORE(mac, tmp);
        tmp = AES_BLOCK_XOR(state[7], state[6]);
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[5], state[4]));
        AES_BLOCK_FOLD_STORE(mac + 16, tmp);
    } else {
        memset(mac, 0, maclen);
    }
}

#include "ciphercommon_aegis_aead.inc"
