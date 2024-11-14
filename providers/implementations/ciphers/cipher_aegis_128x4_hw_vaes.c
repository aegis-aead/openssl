/* aegis-128x4 VAES cipher implementation */

#include <openssl/proverr.h>

#include "ciphercommon_aegis.h"
#include "cipher_aegis_128x4.h"
#include "internal/endian.h"

#ifndef NO_AEGIS
# if defined(__x86_64__) || defined(_M_X64)

#  ifdef __clang__
#   pragma clang attribute push(__attribute__((target("vaes,avx2"))), \
                                apply_to = function)
#  elif defined(__GNUC__)
#   pragma GCC target("vaes,avx2")
#  endif

#  include <immintrin.h>

typedef struct {
    __m256i lo;
    __m256i hi;
} aes_block_t;

static inline aes_block_t AES_BLOCK_XOR(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t){ _mm256_xor_si256(a.lo, b.lo),
                          _mm256_xor_si256(a.hi, b.hi) };
}

static inline aes_block_t AES_BLOCK_AND(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t){ _mm256_and_si256(a.lo, b.lo),
                          _mm256_and_si256(a.hi, b.hi) };
}

static inline aes_block_t AES_BLOCK_LOAD(const uint8_t *a)
{
    return (aes_block_t){
        _mm256_loadu_si256((const __m256i *)(const void *)a),
        _mm256_loadu_si256((const __m256i *)(const void *)(a + 32))
    };
}

static inline aes_block_t AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    const __m256i t = _mm256_broadcastsi128_si256(_mm_set_epi64x((long long)a,
                                                                 (long long)b));
    return (aes_block_t){ t, t };
}

static inline void AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    _mm256_storeu_si256((__m256i *)(void *)a, b.lo);
    _mm256_storeu_si256((__m256i *)(void *)(a + 32), b.hi);
}

static inline aes_block_t AES_ENC(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t){ _mm256_aesenc_epi128(a.lo, b.lo),
                          _mm256_aesenc_epi128(a.hi, b.hi) };
}

#  include "ciphercommon_aegis128x4.inc"

static const PROV_CIPHER_HW_AEGIS_128X4 aegis_128x4_hw_vaes = {
    { aegis_128x4_initkey, NULL },
    aegis_128x4_aead_cipher,
    aegis_128x4_initiv,
    NULL,
    NULL,
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_aegis_128x4_vaes(size_t keybits)
{
    return (PROV_CIPHER_HW *)&aegis_128x4_hw_vaes;
}

#  ifdef __clang__
#   pragma clang attribute pop
#  endif

# endif
#endif
