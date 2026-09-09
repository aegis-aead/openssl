/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * AEGIS-256X (RFC 10032, section 5.5) with AEGIS_DEGREE lanes. With a
 * single lane, this is AEGIS-256 (section 4).
 * The backend that includes this file defines AEGIS_DEGREE and the
 * aes_block_t vector type.
 */

#define AEGIS_KEYLEN 32
#define AES_BLOCK_LENGTH (16 * AEGIS_DEGREE)
#define RATE AES_BLOCK_LENGTH

typedef aes_block_t aegis_state[6];

static void aegis_update(aes_block_t *const state, const aes_block_t d)
{
    aes_block_t tmp;

    tmp = state[5];
    state[5] = AES_ENC(state[4], state[5]);
    state[4] = AES_ENC(state[3], state[4]);
    state[3] = AES_ENC(state[2], state[3]);
    state[2] = AES_ENC(state[1], state[2]);
    state[1] = AES_ENC(state[0], state[1]);
    state[0] = AES_ENC(tmp, state[0]);

    state[0] = AES_BLOCK_XOR(state[0], d);
}

static void aegis_state_init(PROV_AEGIS_CTX *const ctx)
{
    static const uint8_t c0_[] = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08,
        0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 };
    static const uint8_t c1_[] = { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f,
        0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd };
    aegis_state state;
    const aes_block_t c0 = AES_BLOCK_LOAD128_BROADCAST(c0_);
    const aes_block_t c1 = AES_BLOCK_LOAD128_BROADCAST(c1_);
    const aes_block_t k0 = AES_BLOCK_LOAD128_BROADCAST(ctx->key);
    const aes_block_t k1 = AES_BLOCK_LOAD128_BROADCAST(ctx->key + 16);
    const aes_block_t n0 = AES_BLOCK_LOAD128_BROADCAST(ctx->nonce);
    const aes_block_t n1 = AES_BLOCK_LOAD128_BROADCAST(ctx->nonce + 16);
    /* Absorbed in turn during initialization */
    const aes_block_t m[4] = {
        k0, k1, AES_BLOCK_XOR(k0, n0), AES_BLOCK_XOR(k1, n1)
    };
#if AEGIS_DEGREE > 1
    uint8_t context_bytes[AES_BLOCK_LENGTH] = { 0 };
    aes_block_t context;
#endif /* AEGIS_DEGREE > 1 */
    int i;

#if AEGIS_DEGREE > 1
    /* ctx[i] = ZeroPad(Byte(i) || Byte(D - 1), 128) */
    for (i = 0; i < AEGIS_DEGREE; i++) {
        context_bytes[i * 16] = (uint8_t)i;
        context_bytes[i * 16 + 1] = (uint8_t)(AEGIS_DEGREE - 1);
    }
    context = AES_BLOCK_LOAD(context_bytes);
#endif /* AEGIS_DEGREE > 1 */

    state[0] = m[2];
    state[1] = m[3];
    state[2] = c1;
    state[3] = c0;
    state[4] = AES_BLOCK_XOR(k0, c0);
    state[5] = AES_BLOCK_XOR(k1, c1);

    /* Repeat(4, Update(k0), Update(k1), Update(k0 ^ n0), Update(k1 ^ n1)) */
    for (i = 0; i < 16; i++) {
#if AEGIS_DEGREE > 1
        state[3] = AES_BLOCK_XOR(state[3], context);
        state[5] = AES_BLOCK_XOR(state[5], context);
#endif /* AEGIS_DEGREE > 1 */
        aegis_update(state, m[i % 4]);
    }

    memcpy(ctx->state, &state, sizeof state);
}

static ossl_inline void aegis_absorb(const uint8_t *const src,
    aes_block_t *const state)
{
    aegis_update(state, AES_BLOCK_LOAD(src));
}

static void aegis_enc(uint8_t *const dst, const uint8_t *const src,
    aes_block_t *const state)
{
    aes_block_t msg;
    aes_block_t tmp;

    msg = AES_BLOCK_LOAD(src);
    tmp = AES_BLOCK_XOR(msg, state[5]);
    tmp = AES_BLOCK_XOR(tmp, state[4]);
    tmp = AES_BLOCK_XOR(tmp, state[1]);
    tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_AND(state[2], state[3]));
    AES_BLOCK_STORE(dst, tmp);

    aegis_update(state, msg);
}

static void aegis_squeeze_keystream(uint8_t *const dst,
    aes_block_t *const state)
{
    aes_block_t tmp;

    tmp = AES_BLOCK_XOR(state[5], state[4]);
    tmp = AES_BLOCK_XOR(tmp, state[1]);
    tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_AND(state[2], state[3]));
    AES_BLOCK_STORE(dst, tmp);
}

static void aegis_dec(uint8_t *const dst, const uint8_t *const src,
    aes_block_t *const state)
{
    aes_block_t msg;

    msg = AES_BLOCK_LOAD(src);
    msg = AES_BLOCK_XOR(msg, state[5]);
    msg = AES_BLOCK_XOR(msg, state[4]);
    msg = AES_BLOCK_XOR(msg, state[1]);
    msg = AES_BLOCK_XOR(msg, AES_BLOCK_AND(state[2], state[3]));
    AES_BLOCK_STORE(dst, msg);

    aegis_update(state, msg);
}

static void aegis_mac(uint8_t *mac, size_t maclen, uint64_t adlen,
    uint64_t mlen, aes_block_t *const state)
{
    aes_block_t tmp;
    int i;

    tmp = AES_BLOCK_LOAD_64x2(mlen << 3, adlen << 3);
    tmp = AES_BLOCK_XOR(tmp, state[3]);

    for (i = 0; i < 7; i++)
        aegis_update(state, tmp);
    if (maclen == 16) {
        tmp = AES_BLOCK_XOR(state[5], state[4]);
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[3], state[2]));
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[1], state[0]));
        AES_BLOCK_FOLD_STORE(mac, tmp);
    } else if (maclen == 32) {
        tmp = AES_BLOCK_XOR(state[2], state[1]);
        tmp = AES_BLOCK_XOR(tmp, state[0]);
        AES_BLOCK_FOLD_STORE(mac, tmp);
        tmp = AES_BLOCK_XOR(state[5], state[4]);
        tmp = AES_BLOCK_XOR(tmp, state[3]);
        AES_BLOCK_FOLD_STORE(mac + 16, tmp);
    } else {
        memset(mac, 0, maclen);
    }
}

#include "ciphercommon_aegis_aead.inc"
