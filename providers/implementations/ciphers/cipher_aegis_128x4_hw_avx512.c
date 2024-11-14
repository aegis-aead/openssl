/* aegis-128x4 AVX512+VAES cipher implementation */

#include <openssl/proverr.h>

#include "ciphercommon_aegis.h"
#include "cipher_aegis_128x4.h"
#include "internal/endian.h"

#ifndef NO_AEGIS
# if defined(__x86_64__) || defined(_M_X64)

#  ifdef __clang__
#   if __clang_major__ >= 18
#    pragma clang attribute push(__attribute__((target("aes,vaes,avx512f,evex512"))), \
                                 apply_to = function)
#   else
#    pragma clang attribute push(__attribute__((target("aes,vaes,avx512f"))), \
                                 apply_to = function)
#   endif
#  elif defined(__GNUC__)
#   pragma GCC target("aes,vaes,avx512f")
#  endif

#  include <immintrin.h>

typedef __m512i aes_block_t;

static inline aes_block_t AES_BLOCK_XOR(const aes_block_t a, const aes_block_t b)
{
    return _mm512_xor_si512(a, b);
}

static inline aes_block_t AES_BLOCK_AND(const aes_block_t a, const aes_block_t b)
{
    return _mm512_and_si512(a, b);
}

static inline aes_block_t AES_BLOCK_LOAD(const uint8_t *a)
{
    return _mm512_loadu_si512((const void *)a);
}

static inline aes_block_t AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    return _mm512_broadcast_i32x4(_mm_set_epi64x((long long)a, (long long)b));
}

static inline void AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    _mm512_storeu_si512((void *)a, b);
}

static inline aes_block_t AES_ENC(const aes_block_t a, const aes_block_t b)
{
    return _mm512_aesenc_epi128(a, b);
}

#  include "ciphercommon_aegis128x4.inc"

static const PROV_CIPHER_HW_AEGIS_128X4 aegis_128x4_hw_avx512 = {
    { aegis_128x4_initkey, NULL },
    aegis_128x4_aead_cipher,
    aegis_128x4_initiv,
    NULL,
    NULL,
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_aegis_128x4_avx512(size_t keybits)
{
    return (PROV_CIPHER_HW *)&aegis_128x4_hw_avx512;
}

#  ifdef __clang__
#   pragma clang attribute pop
#  endif

# endif
#endif
