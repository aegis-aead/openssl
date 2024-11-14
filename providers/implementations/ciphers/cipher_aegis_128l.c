/* Dispatch functions for aegis-128l cipher */

#include <openssl/proverr.h>

#include "cipher_aegis_128l.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

#define AEGIS_128L_KEYLEN 16
#define AEGIS_128L_BLKLEN 1
#define AEGIS_128L_MAX_IVLEN 16
#define AEGIS_128L_MODE 0
#define AEGIS_128L_FLAGS (PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV)

static OSSL_FUNC_cipher_newctx_fn aegis_128l_newctx;
static OSSL_FUNC_cipher_freectx_fn aegis_128l_freectx;
static OSSL_FUNC_cipher_dupctx_fn aegis_128l_dupctx;
static OSSL_FUNC_cipher_encrypt_init_fn aegis_128l_einit;
static OSSL_FUNC_cipher_decrypt_init_fn aegis_128l_dinit;
static OSSL_FUNC_cipher_get_params_fn aegis_128l_get_params;
static OSSL_FUNC_cipher_get_ctx_params_fn aegis_128l_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn aegis_128l_set_ctx_params;
static OSSL_FUNC_cipher_cipher_fn aegis_128l_cipher;
static OSSL_FUNC_cipher_final_fn aegis_128l_final;
static OSSL_FUNC_cipher_gettable_ctx_params_fn aegis_128l_gettable_ctx_params;
#define aegis_128l_settable_ctx_params ossl_cipher_aead_settable_ctx_params
#define aegis_128l_gettable_params ossl_cipher_generic_gettable_params
#define aegis_128l_update aegis_128l_cipher

static void *aegis_128l_newctx(void *provctx)
{
    PROV_AEGIS_128L_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {
        ossl_cipher_generic_initkey(
            &ctx->base, AEGIS_128L_KEYLEN * 8, AEGIS_128L_BLKLEN * 8,
            AEGIS_128L_IVLEN * 8, AEGIS_128L_MODE, AEGIS_128L_FLAGS,
            ossl_prov_cipher_hw_aegis_128l(AEGIS_128L_KEYLEN * 8), NULL);
        ctx->tag_len = EVP_AEGIS_128L_TLS_TAG_LEN;
    }
    return ctx;
}

static void *aegis_128l_dupctx(void *provctx)
{
    PROV_AEGIS_128L_CTX *ctx = provctx;
    PROV_AEGIS_128L_CTX *dctx = NULL;

    if (ctx == NULL)
        return NULL;
    dctx = OPENSSL_memdup(ctx, sizeof(*ctx));
    if (dctx != NULL && dctx->base.tlsmac != NULL && dctx->base.alloced) {
        dctx->base.tlsmac = OPENSSL_memdup(dctx->base.tlsmac,
                                           dctx->base.tlsmacsize);
        if (dctx->base.tlsmac == NULL) {
            OPENSSL_free(dctx);
            dctx = NULL;
        }
    }
    return dctx;
}

static void aegis_128l_freectx(void *vctx)
{
    PROV_AEGIS_128L_CTX *ctx = (PROV_AEGIS_128L_CTX *)vctx;

    if (ctx != NULL) {
        ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX *)vctx);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

const OSSL_DISPATCH ossl_aegis_128l_functions[] = {
    {             OSSL_FUNC_CIPHER_NEWCTX,(void (*)(void))aegis_128l_newctx                                          },
    {            OSSL_FUNC_CIPHER_FREECTX,    (void (*)(void))aegis_128l_freectx},
    {             OSSL_FUNC_CIPHER_DUPCTX,     (void (*)(void))aegis_128l_dupctx},
    {       OSSL_FUNC_CIPHER_ENCRYPT_INIT,      (void (*)(void))aegis_128l_einit},
    {       OSSL_FUNC_CIPHER_DECRYPT_INIT,      (void (*)(void))aegis_128l_dinit},
    {             OSSL_FUNC_CIPHER_UPDATE,     (void (*)(void))aegis_128l_update},
    {              OSSL_FUNC_CIPHER_FINAL,      (void (*)(void))aegis_128l_final},
    {             OSSL_FUNC_CIPHER_CIPHER,     (void (*)(void))aegis_128l_cipher},
    {         OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))aegis_128l_get_params},
    {    OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
     (void (*)(void))aegis_128l_gettable_params                                 },
    {     OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
     (void (*)(void))aegis_128l_get_ctx_params                                  },
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
     (void (*)(void))aegis_128l_gettable_ctx_params                             },
    {     OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
     (void (*)(void))aegis_128l_set_ctx_params                                  },
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
     (void (*)(void))aegis_128l_settable_ctx_params                             },
    OSSL_DISPATCH_END
};

static int aegis_128l_get_params(OSSL_PARAM params[])
{
    return ossl_cipher_generic_get_params(params, 0, AEGIS_128L_FLAGS,
                                          AEGIS_128L_KEYLEN * 8,
                                          AEGIS_128L_BLKLEN * 8,
                                          AEGIS_128L_IVLEN * 8);
}

static int aegis_128l_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_AEGIS_128L_CTX *ctx = (PROV_AEGIS_128L_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_set_size_t(p, AEGIS_128L_IVLEN)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, AEGIS_128L_KEYLEN)) {
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

static const OSSL_PARAM aegis_128l_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0), OSSL_PARAM_END
};

static const OSSL_PARAM *aegis_128l_gettable_ctx_params(
    ossl_unused void *cctx, ossl_unused void *provctx)
{
    return aegis_128l_known_gettable_ctx_params;
}

static int aegis_128l_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    size_t len;
    PROV_AEGIS_128L_CTX *ctx = (PROV_AEGIS_128L_CTX *)vctx;

    if (ossl_param_is_empty(params))
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != AEGIS_128L_KEYLEN) {
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
        if (len != AEGIS_128L_MAX_IVLEN) {
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

static int aegis_128l_einit(void *vctx, const unsigned char *key, size_t keylen,
                            const unsigned char *iv, size_t ivlen,
                            const OSSL_PARAM params[])
{
    int ret;

    /* The generic function checks for ossl_prov_is_running() */
    ret = ossl_cipher_generic_einit(vctx, key, keylen, iv, ivlen, NULL);
    if (ret && iv != NULL) {
        PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
        PROV_CIPHER_HW_AEGIS_128L *hw = (PROV_CIPHER_HW_AEGIS_128L *)ctx->hw;

        hw->initiv(ctx);
    }
    if (ret && !aegis_128l_set_ctx_params(vctx, params))
        ret = 0;
    return ret;
}

static int aegis_128l_dinit(void *vctx, const unsigned char *key, size_t keylen,
                            const unsigned char *iv, size_t ivlen,
                            const OSSL_PARAM params[])
{
    int ret;

    /* The generic function checks for ossl_prov_is_running() */
    ret = ossl_cipher_generic_dinit(vctx, key, keylen, iv, ivlen, NULL);
    if (ret && iv != NULL) {
        PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
        PROV_CIPHER_HW_AEGIS_128L *hw = (PROV_CIPHER_HW_AEGIS_128L *)ctx->hw;

        hw->initiv(ctx);
    }
    if (ret && !aegis_128l_set_ctx_params(vctx, params))
        ret = 0;
    return ret;
}

static int aegis_128l_cipher(void *vctx, unsigned char *out, size_t *outl,
                             size_t outsize, const unsigned char *in,
                             size_t inl)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    PROV_CIPHER_HW_AEGIS_128L *hw = (PROV_CIPHER_HW_AEGIS_128L *)ctx->hw;

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

static int aegis_128l_final(void *vctx, unsigned char *out, size_t *outl,
                            size_t outsize)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    PROV_CIPHER_HW_AEGIS_128L *hw = (PROV_CIPHER_HW_AEGIS_128L *)ctx->hw;

    if (!ossl_prov_is_running())
        return 0;

    if (hw->aead_cipher(ctx, out, outl, NULL, 0) <= 0)
        return 0;

    *outl = 0;
    return 1;
}
