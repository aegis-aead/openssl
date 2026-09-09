/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Provider functions shared by the AEGIS-128X4, AEGIS-256, AEGIS-256X2 and
 * AEGIS-256X4 ciphers.
 *
 * The file that includes it defines the key and nonce lengths
 * (AEGIS_KEYLEN, AEGIS_IVLEN), the name of the dispatch table
 * (AEGIS_FUNCTIONS) and the backend getters (AEGIS_HW_*).
 */

#include <openssl/proverr.h>

#include "cipher_aegis.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

#define AEGIS_BLKLEN 1
#define AEGIS_MODE 0
#define AEGIS_FLAGS (PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV)

/* Picks the fastest backend this CPU supports */
static const PROV_CIPHER_HW *aegis_select_hw(size_t keybits)
{
#if defined(__x86_64__) || defined(_M_X64)
#if defined(AEGIS_HW_AVX512)
    if (aegis_cpu_has_vaes_avx512())
        return AEGIS_HW_AVX512(keybits);
#endif /* defined(AEGIS_HW_AVX512) */
#if defined(AEGIS_HW_VAES)
    if (aegis_cpu_has_vaes_avx2())
        return AEGIS_HW_VAES(keybits);
#endif /* defined(AEGIS_HW_VAES) */
    if (aegis_cpu_has_aesni())
        return AEGIS_HW_AESNI(keybits);
#elif defined(__aarch64__) || defined(_M_ARM64)
    if (aegis_cpu_has_armv8_aes())
        return AEGIS_HW_NEON(keybits);
#endif /* defined(__x86_64__) || defined(_M_X64) */
    return AEGIS_HW_SOFT(keybits);
}

static OSSL_FUNC_cipher_newctx_fn aegis_newctx;
static OSSL_FUNC_cipher_freectx_fn aegis_freectx;
static OSSL_FUNC_cipher_dupctx_fn aegis_dupctx;
static OSSL_FUNC_cipher_encrypt_init_fn aegis_einit;
static OSSL_FUNC_cipher_decrypt_init_fn aegis_dinit;
static OSSL_FUNC_cipher_get_params_fn aegis_get_params;
static OSSL_FUNC_cipher_get_ctx_params_fn aegis_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn aegis_set_ctx_params;
static OSSL_FUNC_cipher_cipher_fn aegis_cipher;
static OSSL_FUNC_cipher_final_fn aegis_final;
static OSSL_FUNC_cipher_gettable_ctx_params_fn aegis_gettable_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn aegis_settable_ctx_params;
#define aegis_gettable_params ossl_cipher_generic_gettable_params
static OSSL_FUNC_cipher_update_fn aegis_update;

static void *aegis_newctx(void *provctx)
{
    PROV_AEGIS_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {
        ossl_cipher_generic_initkey(
            &ctx->base, AEGIS_KEYLEN * 8, AEGIS_BLKLEN * 8,
            AEGIS_IVLEN * 8, AEGIS_MODE, AEGIS_FLAGS,
            aegis_select_hw(AEGIS_KEYLEN * 8), NULL);
        ctx->tag_len = EVP_AEGIS_TLS_TAG_LEN;
    }
    return ctx;
}

static void *aegis_dupctx(void *provctx)
{
    PROV_AEGIS_CTX *ctx = provctx;
    PROV_AEGIS_CTX *dctx = NULL;

    if (ctx == NULL)
        return NULL;
    dctx = OPENSSL_memdup(ctx, sizeof(*ctx));
    if (dctx != NULL
        && !ossl_cipher_generic_dupctx_tlsmac(&dctx->base, &ctx->base)) {
        OPENSSL_free(dctx);
        dctx = NULL;
    }
    return dctx;
}

static void aegis_freectx(void *vctx)
{
    PROV_AEGIS_CTX *ctx = (PROV_AEGIS_CTX *)vctx;

    if (ctx != NULL) {
        ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX *)vctx);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

const OSSL_DISPATCH AEGIS_FUNCTIONS[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))aegis_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))aegis_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))aegis_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))aegis_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))aegis_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))aegis_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))aegis_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))aegis_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))aegis_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
        (void (*)(void))aegis_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
        (void (*)(void))aegis_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        (void (*)(void))aegis_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
        (void (*)(void))aegis_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        (void (*)(void))aegis_settable_ctx_params },
    OSSL_DISPATCH_END
};

static int aegis_get_params(OSSL_PARAM params[])
{
    return ossl_cipher_generic_get_params(params, 0, AEGIS_FLAGS,
        AEGIS_KEYLEN * 8,
        AEGIS_BLKLEN * 8,
        AEGIS_IVLEN * 8);
}

static int aegis_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_AEGIS_CTX *ctx = (PROV_AEGIS_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_set_size_t(p, AEGIS_IVLEN)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, AEGIS_KEYLEN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tag_len)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        if (!ctx->base.enc) {
            ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
            return 0;
        }
        if (p->data_size != 16 && p->data_size != 32) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return 0;
        }
        memcpy(p->data, ctx->tag, p->data_size);
    }

    return 1;
}

static const OSSL_PARAM aegis_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0), OSSL_PARAM_END
};

static const OSSL_PARAM *aegis_gettable_ctx_params(
    ossl_unused void *cctx, ossl_unused void *provctx)
{
    return aegis_known_gettable_ctx_params;
}

static int aegis_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    size_t len;
    PROV_AEGIS_CTX *ctx = (PROV_AEGIS_CTX *)vctx;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != AEGIS_KEYLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != AEGIS_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (p->data_size != 16 && p->data_size != 32) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return 0;
        }
        if (p->data != NULL) {
            if (ctx->base.enc) {
                ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_NEEDED);
                return 0;
            }
            memcpy(ctx->tag, p->data, p->data_size);
        }
        ctx->tag_len = p->data_size;
    }

    /* ignore OSSL_CIPHER_PARAM_AEAD_MAC_KEY */
    return 1;
}

static const OSSL_PARAM aegis_settable_ctx_params_list[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *aegis_settable_ctx_params(ossl_unused void *cctx,
    ossl_unused void *provctx)
{
    return aegis_settable_ctx_params_list;
}

/* The nonce goes in the AEGIS context, see PROV_AEGIS_CTX */
static int aegis_init(void *vctx, const unsigned char *key,
    size_t keylen, const unsigned char *iv,
    size_t ivlen, const OSSL_PARAM params[], int enc)
{
    PROV_AEGIS_CTX *actx = (PROV_AEGIS_CTX *)vctx;
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    int ret;

    if (iv != NULL) {
        if (ivlen != AEGIS_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        memcpy(actx->nonce, iv, AEGIS_IVLEN);
        ctx->iv_set = 1;
    }

    /* The generic functions check for ossl_prov_is_running() */
    if (enc)
        ret = ossl_cipher_generic_einit(vctx, key, keylen, NULL, 0, NULL);
    else
        ret = ossl_cipher_generic_dinit(vctx, key, keylen, NULL, 0, NULL);

    /* With a new key, the state was already set up when setting the key */
    if (ret && iv != NULL && key == NULL) {
        PROV_CIPHER_HW_AEGIS *hw = (PROV_CIPHER_HW_AEGIS *)ctx->hw;

        hw->initiv(ctx);
    }
    if (ret && !aegis_set_ctx_params(vctx, params))
        ret = 0;
    return ret;
}

static int aegis_einit(void *vctx, const unsigned char *key,
    size_t keylen, const unsigned char *iv,
    size_t ivlen, const OSSL_PARAM params[])
{
    return aegis_init(vctx, key, keylen, iv, ivlen, params, 1);
}

static int aegis_dinit(void *vctx, const unsigned char *key,
    size_t keylen, const unsigned char *iv,
    size_t ivlen, const OSSL_PARAM params[])
{
    return aegis_init(vctx, key, keylen, iv, ivlen, params, 0);
}

static int aegis_update(void *vctx, unsigned char *out, size_t *outl,
    size_t outsize, const unsigned char *in,
    size_t inl)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    PROV_CIPHER_HW_AEGIS *hw = (PROV_CIPHER_HW_AEGIS *)ctx->hw;

    if (!ossl_prov_is_running())
        return 0;

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!hw->aead_cipher(ctx, out, outl, in, inl))
        return 0;

    return 1;
}

static int aegis_cipher(void *vctx, unsigned char *out, size_t *outl,
    size_t outsize, const unsigned char *in, size_t inl)
{
    /* Only the one-shot interface finalizes when passed a NULL input. */
    if (in == NULL)
        return aegis_final(vctx, out, outl, outsize);

    return aegis_update(vctx, out, outl, outsize, in, inl);
}

static int aegis_final(void *vctx, unsigned char *out, size_t *outl,
    size_t outsize)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    PROV_CIPHER_HW_AEGIS *hw = (PROV_CIPHER_HW_AEGIS *)ctx->hw;

    if (!ossl_prov_is_running())
        return 0;

    if (hw->aead_cipher(ctx, out, outl, NULL, 0) <= 0)
        return 0;

    *outl = 0;
    return 1;
}
