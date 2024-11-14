/* aegis-128x2 cipher implementation */

#include <openssl/proverr.h>

#include "ciphercommon_aegis.h"
#include "cipher_aegis_128x2.h"
#include "internal/cryptlib.h"
#include "internal/endian.h"

#ifndef NO_AEGIS

# if defined(__x86_64__) || defined(_M_X64)

#  ifdef __clang__
#   pragma clang attribute push(__attribute__((target("aes,avx"))), \
                                apply_to = function)
#  elif defined(__GNUC__)
#   pragma GCC target("aes,avx")
#  endif

#  include <immintrin.h>
#  include <wmmintrin.h>

typedef struct {
    __m128i b0;
    __m128i b1;
} aes_block_t;

static inline aes_block_t AES_BLOCK_XOR(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t){ _mm_xor_si128(a.b0, b.b0), _mm_xor_si128(a.b1, b.b1) };
}

static inline aes_block_t AES_BLOCK_AND(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t){ _mm_and_si128(a.b0, b.b0), _mm_and_si128(a.b1, b.b1) };
}

static inline aes_block_t AES_BLOCK_LOAD(const uint8_t *a)
{
    return (aes_block_t){
        _mm_loadu_si128((const __m128i *)(const void *)a),
        _mm_loadu_si128((const __m128i *)(const void *)(a + 16))
    };
}

static inline aes_block_t AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    const __m128i t = _mm_set_epi64x((long long)a, (long long)b);
    return (aes_block_t){ t, t };
}

static inline void AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    _mm_storeu_si128((__m128i *)(void *)a, b.b0);
    _mm_storeu_si128((__m128i *)(void *)(a + 16), b.b1);
}

static inline aes_block_t AES_ENC(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t){ _mm_aesenc_si128(a.b0, b.b0),
                          _mm_aesenc_si128(a.b1, b.b1) };
}

# elif defined(__aarch64__) || defined(_M_ARM64)

#  include <arm_neon.h>

#  ifdef __clang__
#   pragma clang attribute push(__attribute__((target("neon,crypto,aes"))), \
                                apply_to = function)
#  elif defined(__GNUC__)
#   pragma GCC target("+simd+crypto")
#  endif
#  ifndef __ARM_FEATURE_CRYPTO
#   define __ARM_FEATURE_CRYPTO 1
#  endif
#  ifndef __ARM_FEATURE_AES
#   define __ARM_FEATURE_AES 1
#  endif

typedef struct {
    uint8x16_t b0;
    uint8x16_t b1;
} aes_block_t;

static ossl_inline aes_block_t AES_BLOCK_XOR(const aes_block_t a,
                                             const aes_block_t b)
{
    return (aes_block_t){ veorq_u8(a.b0, b.b0), veorq_u8(a.b1, b.b1) };
}

static ossl_inline aes_block_t AES_BLOCK_AND(const aes_block_t a,
                                             const aes_block_t b)
{
    return (aes_block_t){ vandq_u8(a.b0, b.b0), vandq_u8(a.b1, b.b1) };
}

static ossl_inline aes_block_t AES_BLOCK_LOAD(const uint8_t *a)
{
    return (aes_block_t){ vld1q_u8(a), vld1q_u8(a + 16) };
}

static ossl_inline aes_block_t AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    const uint8x16_t t =
        vreinterpretq_u8_u64(vsetq_lane_u64((a), vmovq_n_u64(b), 1));
    return (aes_block_t){ t, t };
}

static ossl_inline void AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    vst1q_u8(a, b.b0);
    vst1q_u8(a + 16, b.b1);
}

static ossl_inline aes_block_t AES_ENC(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t){
        veorq_u8(vaesmcq_u8(vaeseq_u8((a.b0), vmovq_n_u8(0))), (b.b0)),
        veorq_u8(vaesmcq_u8(vaeseq_u8((a.b1), vmovq_n_u8(0))), (b.b1))
    };
}

# else

#  ifdef __clang__
#   pragma clang attribute push(__attribute__((target(""))), \
                                apply_to = function)
#  endif

typedef struct {
    softaes_block_t b0;
    softaes_block_t b1;
} aes_block_t;

static ossl_inline aes_block_t AES_BLOCK_XOR(const aes_block_t a,
                                             const aes_block_t b)
{
    return (aes_block_t){ softaes_block_xor(a.b0, b.b0),
                          softaes_block_xor(a.b1, b.b1) };
}

static ossl_inline aes_block_t AES_BLOCK_AND(const aes_block_t a,
                                             const aes_block_t b)
{
    return (aes_block_t){ softaes_block_and(a.b0, b.b0),
                          softaes_block_and(a.b1, b.b1) };
}

static ossl_inline aes_block_t AES_BLOCK_LOAD(const uint8_t *a)
{
    return (aes_block_t){ softaes_block_load(a), softaes_block_load(a + 16) };
}

static ossl_inline aes_block_t AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    const softaes_block_t t = softaes_block_load64x2(a, b);
    return (aes_block_t){ t, t };
}

static ossl_inline void AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    softaes_block_store(a, b.b0);
    softaes_block_store(a + 16, b.b1);
}

static ossl_inline aes_block_t AES_ENC(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t){ softaes_block_encrypt(a.b0, b.b0),
                          softaes_block_encrypt(a.b1, b.b1) };
}

# endif

# include "ciphercommon_aegis128x2.inc"

static const PROV_CIPHER_HW_AEGIS_128X2 aegis_128x2_hw = {
    {aegis_128x2_initkey, NULL},
    aegis_128x2_aead_cipher,
    aegis_128x2_initiv,
    NULL,
    NULL,
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_aegis_128x2(size_t keybits)
{
# if defined(__x86_64__) || defined(_M_X64)
#  if defined(__VAES__) && defined(__AVX2__)
    const int is_vaes_capable = 1;
    const int is_avx2_capable = 1;
#  else
    const int is_vaes_capable = (OPENSSL_ia32cap_P[3] & (1u << 9)) != 0;
    const int is_avx2_capable = (OPENSSL_ia32cap_P[2] & (1u << 5)) != 0;
#  endif
    if (is_vaes_capable && is_avx2_capable) {
        return ossl_prov_cipher_hw_aegis_128x2_vaes(keybits);
    }
# endif

    return (PROV_CIPHER_HW *)&aegis_128x2_hw;
}

# if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) \
     || defined(_M_ARM64)
#  ifdef __clang__
#   pragma clang attribute pop
#  endif
# endif

#endif
