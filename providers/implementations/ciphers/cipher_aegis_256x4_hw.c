/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* AEGIS-256X4 using the AES instructions of x86-64 or ARMv8 */

#include <openssl/proverr.h>

#include "cipher_aegis.h"

#if defined(__x86_64__) || defined(_M_X64)

#if defined(__clang__)
#pragma clang attribute push(__attribute__((target("aes"))), \
    apply_to = function)
#elif defined(__GNUC__)
#pragma GCC target("aes")
#endif /* defined(__clang__) */

#define AEGIS_DEGREE 4
#include "ciphercommon_aegis_block_aesni.h"
#include "ciphercommon_aegis256x.inc"

AEGIS_DEFINE_HW(256x4_aesni)

#if defined(__clang__)
#pragma clang attribute pop
#endif /* defined(__clang__) */

#elif defined(__aarch64__) || defined(_M_ARM64)

#include <arm_neon.h>

#if defined(__clang__)
#pragma clang attribute push(__attribute__((target("neon,crypto,aes"))), \
    apply_to = function)
#elif defined(__GNUC__)
#pragma GCC target("+simd+crypto")
#endif /* defined(__clang__) */
#if !defined(__ARM_FEATURE_CRYPTO)
#define __ARM_FEATURE_CRYPTO 1
#endif /* !defined(__ARM_FEATURE_CRYPTO) */
#if !defined(__ARM_FEATURE_AES)
#define __ARM_FEATURE_AES 1
#endif /* !defined(__ARM_FEATURE_AES) */

#define AEGIS_DEGREE 4
#include "ciphercommon_aegis_block_neon.h"
#include "ciphercommon_aegis256x.inc"

AEGIS_DEFINE_HW(256x4_neon)

#if defined(__clang__)
#pragma clang attribute pop
#endif /* defined(__clang__) */

#endif /* defined(__x86_64__) || defined(_M_X64) */
