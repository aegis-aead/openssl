/* aegis-128x2 VAES cipher implementation */

#include <openssl/proverr.h>

#include "ciphercommon_aegis.h"
#include "cipher_aegis_128x2.h"
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

typedef __m256i aes_block_t;

#  define AES_BLOCK_XOR(A, B) _mm256_xor_si256((A), (B))
#  define AES_BLOCK_AND(A, B) _mm256_and_si256((A), (B))
#  define AES_BLOCK_LOAD128_BROADCAST(A) \
      _mm256_broadcastsi128_si256(_mm_loadu_si128((const void *)(A)))
#  define AES_BLOCK_LOAD(A) \
      _mm256_loadu_si256((const aes_block_t *)(const void *)(A))
#  define AES_BLOCK_LOAD_64x2(A, B) \
      _mm256_broadcastsi128_si256(_mm_set_epi64x((A), (B)))
#  define AES_BLOCK_STORE(A, B) \
      _mm256_storeu_si256((aes_block_t *)(void *)(A), (B))
#  define AES_ENC(A, B) _mm256_aesenc_epi128((A), (B))

#  include "ciphercommon_aegis128x2.inc"

static const PROV_CIPHER_HW_AEGIS_128X2 aegis_128x2_hw_vaes = {
    {aegis_128x2_initkey, NULL},
    aegis_128x2_aead_cipher,
    aegis_128x2_initiv,
    NULL,
    NULL,
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_aegis_128x2_vaes(size_t keybits)
{
    return (PROV_CIPHER_HW *)&aegis_128x2_hw_vaes;
}

#  ifdef __clang__
#   pragma clang attribute pop
#  endif

# endif
#endif
