/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* AEGIS-256X2 portable implementation */

#include <openssl/proverr.h>

#include "cipher_aegis.h"

#define AEGIS_DEGREE 2
#include "ciphercommon_aegis_block_soft.h"
#include "ciphercommon_aegis256x.inc"

AEGIS_DEFINE_HW(256x2_soft)
