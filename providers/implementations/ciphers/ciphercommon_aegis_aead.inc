/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * The AEAD interface shared by all the AEGIS templates: setting the key and
 * nonce, buffering partial blocks, and computing or checking the tag.
 * It is included at the end of ciphercommon_aegis128x.inc and
 * ciphercommon_aegis256x.inc, which provide the algorithm itself.
 */

static int aegis_initkey(PROV_CIPHER_CTX *bctx, const unsigned char *key,
    size_t keylen)
{
    PROV_AEGIS_CTX *const ctx = (PROV_AEGIS_CTX *)bctx;

    if (keylen != AEGIS_KEYLEN) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }
    memcpy(ctx->key, key, AEGIS_KEYLEN);
    if (bctx->iv_set)
        aegis_state_init(ctx);
    else
        memset(ctx->nonce, 0, sizeof ctx->nonce);
    bctx->key_set = 1;
    ctx->ad_len = 0;
    ctx->msg_len = 0;
    ctx->pos = 0;

    return 1;
}

static int aegis_initiv(PROV_CIPHER_CTX *bctx)
{
    PROV_AEGIS_CTX *const ctx = (PROV_AEGIS_CTX *)bctx;

    if (bctx->key_set)
        aegis_state_init(ctx);
    bctx->iv_set = 1;
    ctx->ad_len = 0;
    ctx->msg_len = 0;
    ctx->pos = 0;

    return 1;
}

static void aegis_ad_update(PROV_AEGIS_CTX *ctx, const uint8_t *ad,
    size_t ad_len)
{
    aegis_state state;
    size_t i;
    size_t left;

    left = ctx->ad_len % RATE;
    ctx->ad_len += ad_len;
    if (left + ad_len < RATE) {
        /* Not a full block yet */
        memcpy(ctx->buf + left, ad, ad_len);
        return;
    }

    memcpy(&state, ctx->state, sizeof state);
    if (left != 0) {
        memcpy(ctx->buf + left, ad, RATE - left);
        aegis_absorb(ctx->buf, state);
        ad += RATE - left;
        ad_len -= RATE - left;
    }
    for (i = 0; i + RATE <= ad_len; i += RATE)
        aegis_absorb(ad + i, state);
    /* Kept for the next call, and zero-padded once all the AD is in */
    memcpy(ctx->buf, ad + i, ad_len - i);

    memcpy(ctx->state, &state, sizeof state);
}

static void aegis_encrypt_final(PROV_AEGIS_CTX *ctx, size_t *written,
    uint8_t *mac, size_t maclen)
{
    aegis_state state;

    memcpy(&state, ctx->state, sizeof state);

    if (ctx->pos != 0) {
        memset(ctx->buf + ctx->pos, 0, RATE - ctx->pos);
        aegis_absorb(ctx->buf, state);
        ctx->pos = 0;
    }
    aegis_mac(mac, maclen, ctx->ad_len, ctx->msg_len, state);
    *written = maclen;
}

static int aegis_decrypt_final(PROV_AEGIS_CTX *ctx, size_t *written,
    const uint8_t *mac, size_t maclen)
{
    aegis_state state;
    uint8_t computed_mac[AEGIS_MAX_TAGLEN];
    int ret = 0;

    memcpy(&state, ctx->state, sizeof state);

    *written = 0;
    if (ctx->pos != 0) {
        memset(ctx->buf + ctx->pos, 0, RATE - ctx->pos);
        aegis_absorb(ctx->buf, state);
        ctx->pos = 0;
    }
    if (maclen <= sizeof computed_mac) {
        aegis_mac(computed_mac, maclen, ctx->ad_len, ctx->msg_len, state);
        ret = CRYPTO_memcmp(computed_mac, mac, maclen) == 0;
    }
    OPENSSL_cleanse(computed_mac, sizeof computed_mac);

    return ret;
}

static void aegis_encrypt_update(PROV_AEGIS_CTX *ctx, size_t *written,
    uint8_t *c, const uint8_t *m, size_t mlen)
{
    aegis_state state;
    size_t i = 0;
    size_t left;

    memcpy(&state, ctx->state, sizeof state);

    *written = 0;
    ctx->msg_len += mlen;

    if (ctx->pos != 0) {
        const size_t available = RATE - ctx->pos;
        const size_t n = mlen < available ? mlen : available;
        size_t j;
        uint8_t tmp;

        for (j = 0; j < n; j++) {
            tmp = m[j];
            c[j] = m[j] ^ ctx->buf[ctx->pos + j];
            ctx->buf[ctx->pos + j] = tmp;
        }
        ctx->pos += n;
        i = n;
        if (ctx->pos < RATE) {
            *written = n;
            return;
        }
        aegis_absorb(ctx->buf, state);
        ctx->pos = 0;
    }
    for (; i + RATE <= mlen; i += RATE)
        aegis_enc(c + i, m + i, state);
    left = mlen - i;
    if (left != 0) {
        size_t j;
        uint8_t tmp;

        aegis_squeeze_keystream(ctx->buf, state);
        for (j = 0; j < left; j++) {
            tmp = m[i + j];
            c[i + j] = m[i + j] ^ ctx->buf[j];
            ctx->buf[j] = tmp;
        }
        ctx->pos = left;
    }
    *written = mlen;

    memcpy(ctx->state, &state, sizeof state);
}

static void aegis_decrypt_update(PROV_AEGIS_CTX *ctx, size_t *written,
    uint8_t *m, const uint8_t *c, size_t clen)
{
    aegis_state state;
    size_t i = 0;
    size_t left;

    memcpy(&state, ctx->state, sizeof state);

    *written = 0;
    ctx->msg_len += clen;

    if (ctx->pos != 0) {
        const size_t available = RATE - ctx->pos;
        const size_t n = clen < available ? clen : available;
        size_t j;

        for (j = 0; j < n; j++) {
            m[j] = c[j] ^ ctx->buf[ctx->pos + j];
            ctx->buf[ctx->pos + j] = m[j];
        }
        ctx->pos += n;
        i = n;
        if (ctx->pos < RATE) {
            *written = n;
            return;
        }
        aegis_absorb(ctx->buf, state);
        ctx->pos = 0;
    }
    for (; i + RATE <= clen; i += RATE)
        aegis_dec(m + i, c + i, state);
    left = clen - i;
    if (left != 0) {
        size_t j;

        aegis_squeeze_keystream(ctx->buf, state);
        for (j = 0; j < left; j++) {
            m[i + j] = c[i + j] ^ ctx->buf[j];
            ctx->buf[j] = m[i + j];
        }
        ctx->pos = left;
    }
    *written = clen;

    memcpy(ctx->state, &state, sizeof state);
}

static int aegis_aead_cipher(PROV_CIPHER_CTX *bctx, unsigned char *out,
    size_t *outl, const unsigned char *in, size_t inl)
{
    PROV_AEGIS_CTX *const ctx = (PROV_AEGIS_CTX *)bctx;
    size_t written = 0;

    if (!bctx->key_set) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    if (!bctx->iv_set) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_NONCE);
        return 0;
    }
    if (outl != NULL)
        *outl = 0;
    /* Pad and absorb the last partial AD block, once, before any message */
    if (ctx->msg_len == 0 && (out != NULL || in == NULL)) {
        size_t left = ctx->ad_len % RATE;

        if (left != 0) {
            aegis_state state;

            memset(ctx->buf + left, 0, RATE - left);
            memcpy(&state, ctx->state, sizeof state);
            aegis_absorb(ctx->buf, state);
            memcpy(ctx->state, &state, sizeof state);
        }
    }
    if (out == NULL && in != NULL) {
        if (ctx->msg_len > 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER);
            return 0;
        }
        aegis_ad_update(ctx, in, inl);
        written = inl;
    } else if (out != NULL && in != NULL) {
        if (bctx->enc)
            aegis_encrypt_update(ctx, &written, out, in, inl);
        else
            aegis_decrypt_update(ctx, &written, out, in, inl);
    } else if (in == NULL) {
        if (bctx->enc) {
            aegis_encrypt_final(ctx, &written, ctx->tag, ctx->tag_len);
        } else if (!aegis_decrypt_final(ctx, &written, ctx->tag,
                       ctx->tag_len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
            return 0;
        }
    } else {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_PARAMETERS);
        return 0;
    }
    if (outl != NULL)
        *outl = written;
    return 1;
}
