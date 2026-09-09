/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* AEGIS-256X4 using VAES and AVX2 */

#include <openssl/proverr.h>

#include "cipher_aegis.h"

#if defined(__x86_64__) || defined(_M_X64)

#if defined(__clang__)
#pragma clang attribute push(__attribute__((target("vaes,avx2"))), \
    apply_to = function)
#elif defined(__GNUC__)
#pragma GCC target("vaes,avx2")
#endif /* defined(__clang__) */

#define AEGIS_DEGREE 4
#include "ciphercommon_aegis_block_vaes.h"
#include "ciphercommon_aegis256x.inc"

AEGIS_DEFINE_HW(256x4_vaes)

#if defined(__clang__)
#pragma clang attribute pop
#endif /* defined(__clang__) */

#endif /* defined(__x86_64__) || defined(_M_X64) */
