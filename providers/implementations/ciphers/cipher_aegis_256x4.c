/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for the AEGIS-256X4 cipher */

#define AEGIS_KEYLEN 32
#define AEGIS_IVLEN 32
#define AEGIS_FUNCTIONS ossl_aegis_256x4_functions
#define AEGIS_HW_SOFT ossl_prov_cipher_hw_aegis_256x4_soft
#define AEGIS_HW_AESNI ossl_prov_cipher_hw_aegis_256x4_aesni
#define AEGIS_HW_NEON ossl_prov_cipher_hw_aegis_256x4_neon
#define AEGIS_HW_VAES ossl_prov_cipher_hw_aegis_256x4_vaes
#define AEGIS_HW_AVX512 ossl_prov_cipher_hw_aegis_256x4_avx512

#include "cipher_aegis_prov.inc"
