/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Shared by AEGIS-128X4, AEGIS-256, AEGIS-256X2 and AEGIS-256X4 (RFC 10032) */

#if !defined(OSSL_PROV_CIPHER_AEGIS_H)
#define OSSL_PROV_CIPHER_AEGIS_H

#include <string.h>

#include "prov/ciphercommon.h"
#include "internal/cryptlib.h"

#if (defined(__aarch64__) || defined(_M_ARM64)) && defined(OPENSSL_CPUID_OBJ)
#include "crypto/arm_arch.h"
#endif /* (defined(__aarch64__) || defined(_M_ARM64)) && defined(OPENSSL_CPUID_OBJ) */

#define AEGIS_MAX_KEYLEN 32
#define AEGIS_MAX_IVLEN 32
#define AEGIS_MAX_TAGLEN 32
/* AEGIS-128X4 has both the largest rate and the largest state */
#define AEGIS_MAX_RATE 128
#define AEGIS_MAX_STATE_SIZE 512

typedef struct {
    PROV_CIPHER_CTX base; /* must be first */
    unsigned char state[AEGIS_MAX_STATE_SIZE]; /* the AEGIS state words */
    unsigned char key[AEGIS_MAX_KEYLEN];
    /* Kept here because PROV_CIPHER_CTX only has room for 16-byte IVs */
    unsigned char nonce[AEGIS_MAX_IVLEN];
    unsigned char tag[AEGIS_MAX_TAGLEN]; /* computed or expected tag */
    /* Partial block: pending AD, or the keystream and message bytes */
    unsigned char buf[AEGIS_MAX_RATE];
    uint64_t ad_len; /* AD bytes so far */
    uint64_t msg_len; /* message bytes so far */
    size_t pos; /* message bytes used in buf */
    size_t tag_len;
} PROV_AEGIS_CTX;

typedef struct {
    PROV_CIPHER_HW base; /* must be first */
    int (*aead_cipher)(PROV_CIPHER_CTX *dat, unsigned char *out, size_t *outl,
        const unsigned char *in, size_t len);
    int (*initiv)(PROV_CIPHER_CTX *ctx);
} PROV_CIPHER_HW_AEGIS;

/* CPU feature checks used to pick the fastest backend */
#if defined(__x86_64__) || defined(_M_X64)
static ossl_inline int aegis_cpu_has_aesni(void)
{
#if defined(__AES__)
    return 1;
#else
    return (OPENSSL_ia32cap_P[1] & (1u << 25)) != 0;
#endif /* defined(__AES__) */
}

static ossl_inline int aegis_cpu_has_vaes_avx2(void)
{
#if defined(__VAES__) && defined(__AVX2__)
    return 1;
#else
    return (OPENSSL_ia32cap_P[3] & (1u << 9)) != 0
        && (OPENSSL_ia32cap_P[2] & (1u << 5)) != 0;
#endif /* defined(__VAES__) && defined(__AVX2__) */
}

static ossl_inline int aegis_cpu_has_vaes_avx512(void)
{
#if defined(__VAES__) && defined(__AVX512F__)
    return 1;
#else
    return (OPENSSL_ia32cap_P[3] & (1u << 9)) != 0
        && (OPENSSL_ia32cap_P[2] & (1u << 16)) != 0;
#endif /* defined(__VAES__) && defined(__AVX512F__) */
}
#elif defined(__aarch64__) || defined(_M_ARM64)
static ossl_inline int aegis_cpu_has_armv8_aes(void)
{
#if defined(__ARM_FEATURE_AES) || defined(__ARM_FEATURE_CRYPTO)
    return 1;
#elif defined(OPENSSL_CPUID_OBJ)
    return (OPENSSL_armcap_P & ARMV8_AES) != 0;
#else
    return 0;
#endif /* defined(__ARM_FEATURE_AES) || defined(__ARM_FEATURE_CRYPTO) */
}
#endif /* defined(__x86_64__) || defined(_M_X64) */

#define AEGIS_DECLARE_HW(name) \
    const PROV_CIPHER_HW *ossl_prov_cipher_hw_aegis_##name(size_t keybits)

AEGIS_DECLARE_HW(128x4_soft);
AEGIS_DECLARE_HW(256_soft);
AEGIS_DECLARE_HW(256x2_soft);
AEGIS_DECLARE_HW(256x4_soft);
#if defined(__x86_64__) || defined(_M_X64)
AEGIS_DECLARE_HW(128x4_aesni);
AEGIS_DECLARE_HW(128x4_vaes);
AEGIS_DECLARE_HW(128x4_avx512);
AEGIS_DECLARE_HW(256_aesni);
AEGIS_DECLARE_HW(256x2_aesni);
AEGIS_DECLARE_HW(256x2_vaes);
AEGIS_DECLARE_HW(256x4_aesni);
AEGIS_DECLARE_HW(256x4_vaes);
AEGIS_DECLARE_HW(256x4_avx512);
#elif defined(__aarch64__) || defined(_M_ARM64)
AEGIS_DECLARE_HW(128x4_neon);
AEGIS_DECLARE_HW(256_neon);
AEGIS_DECLARE_HW(256x2_neon);
AEGIS_DECLARE_HW(256x4_neon);
#endif /* defined(__x86_64__) || defined(_M_X64) */

/* Defines a backend getter, after an algorithm template has been included */
#define AEGIS_DEFINE_HW(name)                      \
    static const PROV_CIPHER_HW_AEGIS aegis_hw = { \
        { aegis_initkey, NULL },                   \
        aegis_aead_cipher,                         \
        aegis_initiv,                              \
    };                                             \
    AEGIS_DECLARE_HW(name)                         \
    {                                              \
        return (const PROV_CIPHER_HW *)&aegis_hw;  \
    }

#endif /* !defined(OSSL_PROV_CIPHER_AEGIS_H) */
