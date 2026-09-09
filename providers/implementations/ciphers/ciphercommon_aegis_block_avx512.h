/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* AEGIS vector of 4 AES blocks, using VAES on AVX-512 registers */

#if !defined(OSSL_PROV_CIPHERCOMMON_AEGIS_BLOCK_AVX512_H)
#define OSSL_PROV_CIPHERCOMMON_AEGIS_BLOCK_AVX512_H

#include <immintrin.h>

#if AEGIS_DEGREE != 4
#error "the AVX-512 backend needs exactly 4 AES blocks"
#endif /* AEGIS_DEGREE != 4 */

typedef __m512i aes_block_t;

#define AES_BLOCK_XOR(A, B) _mm512_xor_si512((A), (B))
#define AES_BLOCK_AND(A, B) _mm512_and_si512((A), (B))
#define AES_BLOCK_LOAD(A) _mm512_loadu_si512((const void *)(A))
#define AES_BLOCK_LOAD128_BROADCAST(A) \
    _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i *)(const void *)(A)))
#define AES_BLOCK_LOAD_64x2(A, B) \
    _mm512_broadcast_i32x4(_mm_set_epi64x((long long)(A), (long long)(B)))
#define AES_BLOCK_STORE(A, B) _mm512_storeu_si512((void *)(A), (B))
#define AES_ENC(A, B) _mm512_aesenc_epi128((A), (B))

/* Stores all the lanes XORed together, as 16 bytes */
static ossl_inline void AES_BLOCK_FOLD_STORE(uint8_t *a, const aes_block_t b)
{
    const __m128i t = _mm_xor_si128(
        _mm_xor_si128(_mm512_extracti32x4_epi32(b, 0),
            _mm512_extracti32x4_epi32(b, 1)),
        _mm_xor_si128(_mm512_extracti32x4_epi32(b, 2),
            _mm512_extracti32x4_epi32(b, 3)));

    _mm_storeu_si128((__m128i *)(void *)a, t);
}

#endif /* !defined(OSSL_PROV_CIPHERCOMMON_AEGIS_BLOCK_AVX512_H) */
