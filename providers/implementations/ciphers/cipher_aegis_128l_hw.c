/* aegis-128l cipher implementation */

#include <openssl/proverr.h>

#include "cipher_aegis_128l.h"
#include "internal/endian.h"

#if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) \
    || defined(_M_ARM64)

# if defined(__x86_64__) || defined(_M_X64)
#  ifdef __clang__
#   pragma clang attribute push(__attribute__((target("aes,avx"))), \
                                apply_to = function)
#  elif defined(__GNUC__)
#   pragma GCC target("aes,avx")
#  endif

#  include <wmmintrin.h>

typedef __m128i aes_block_t;
#  define AES_BLOCK_XOR(A, B) _mm_xor_si128((A), (B))
#  define AES_BLOCK_AND(A, B) _mm_and_si128((A), (B))
#  define AES_BLOCK_LOAD(A) \
      _mm_loadu_si128((const aes_block_t *)(const void *)(A))
#  define AES_BLOCK_LOAD_64x2(A, B) _mm_set_epi64x((A), (B))
#  define AES_BLOCK_STORE(A, B) \
      _mm_storeu_si128((aes_block_t *)(void *)(A), (B))
#  define AES_ENC(A, B) _mm_aesenc_si128((A), (B))

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

typedef uint8x16_t aes_block_t;
#  define AES_BLOCK_XOR(A, B) veorq_u8((A), (B))
#  define AES_BLOCK_AND(A, B) vandq_u8((A), (B))
#  define AES_BLOCK_LOAD(A) vld1q_u8(A)
#  define AES_BLOCK_LOAD_64x2(A, B) \
      vreinterpretq_u8_u64(vsetq_lane_u64((A), vmovq_n_u64(B), 1))
#  define AES_BLOCK_STORE(A, B) vst1q_u8((A), (B))
#  define AES_ENC(A, B) veorq_u8(vaesmcq_u8(vaeseq_u8((A), vmovq_n_u8(0))), (B))

# else
#  error "Unsupported architecture"
# endif

# define AES_BLOCK_LENGTH 16
# define RATE AEGIS_128L_RATE

typedef aes_block_t aegis_128l_state[8];

static void aegis_128l_update(aes_block_t * const state, const aes_block_t d1,
                              const aes_block_t d2)
{
    aes_block_t tmp;

    tmp = state[7];
    state[7] = AES_ENC(state[6], state[7]);
    state[6] = AES_ENC(state[5], state[6]);
    state[5] = AES_ENC(state[4], state[5]);
    state[4] = AES_ENC(state[3], state[4]);
    state[3] = AES_ENC(state[2], state[3]);
    state[2] = AES_ENC(state[1], state[2]);
    state[1] = AES_ENC(state[0], state[1]);
    state[0] = AES_ENC(tmp, state[0]);

    state[0] = AES_BLOCK_XOR(state[0], d1);
    state[4] = AES_BLOCK_XOR(state[4], d2);
}

static void aegis_128l_state_init(PROV_CIPHER_CTX * const bctx)
{
    aegis_128l_state st;
    PROV_AEGIS_128L_CTX * const ctx = (PROV_AEGIS_128L_CTX *)bctx;
    const uint8_t * const key = ctx->key;
    const uint8_t * const nonce = bctx->iv;

    static const uint8_t c0_[] = { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2,
                                   0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42,
                                   0x73, 0xb5, 0x28, 0xdd };
    static const uint8_t c1_[] = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05,
                                   0x08, 0x0d, 0x15, 0x22, 0x37, 0x59,
                                   0x90, 0xe9, 0x79, 0x62 };
    const aes_block_t c0 = AES_BLOCK_LOAD(c0_);
    const aes_block_t c1 = AES_BLOCK_LOAD(c1_);

    aes_block_t k = AES_BLOCK_LOAD(key);
    aes_block_t n = AES_BLOCK_LOAD(nonce);

    memcpy(st, ctx->state, sizeof st);

    st[0] = AES_BLOCK_XOR(k, n);
    st[1] = c0;
    st[2] = c1;
    st[3] = c0;
    st[4] = AES_BLOCK_XOR(k, n);
    st[5] = AES_BLOCK_XOR(k, c1);
    st[6] = AES_BLOCK_XOR(k, c0);
    st[7] = AES_BLOCK_XOR(k, c1);

    for (int i = 0; i < 10; i++) {
        aegis_128l_update(st, n, k);
    }

    memcpy(ctx->state, st, sizeof ctx->state);
}

static int aegis_128l_initkey(PROV_CIPHER_CTX *bctx, const unsigned char *key,
                              size_t keylen)
{
    PROV_AEGIS_128L_CTX * const ctx = (PROV_AEGIS_128L_CTX *)bctx;

    if (keylen != sizeof ctx->key) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }
    memcpy(ctx->key, key, sizeof ctx->key);
    if (bctx->iv_set) {
        aegis_128l_state_init(bctx);
    } else {
        memset(bctx->iv, 0, AEGIS_128L_IVLEN);
    }
    bctx->key_set = 1;
    ctx->ad_len = 0;
    ctx->msg_len = 0;
    ctx->pos = 0;

    return 1;
}

static int aegis_128l_initiv(PROV_CIPHER_CTX *bctx)
{
    PROV_AEGIS_128L_CTX * const ctx = (PROV_AEGIS_128L_CTX *)bctx;

    if (bctx->key_set) {
        aegis_128l_state_init(bctx);
    }
    bctx->iv_set = 1;
    ctx->ad_len = 0;
    ctx->msg_len = 0;
    ctx->pos = 0;

    return 1;
}

static inline void aegis_128l_absorb(const uint8_t * const src,
                                     aes_block_t * const state)
{
    aes_block_t msg0, msg1;

    msg0 = AES_BLOCK_LOAD(src);
    msg1 = AES_BLOCK_LOAD(src + AES_BLOCK_LENGTH);
    aegis_128l_update(state, msg0, msg1);
}

static void aegis_128l_ad_update(PROV_AEGIS_128L_CTX *ctx, const uint8_t *ad,
                                 size_t ad_len)
{
    aegis_128l_state st;
    size_t i;
    size_t left;

    memcpy(st, ctx->state, sizeof st);

    left = ctx->ad_len % RATE;
    ctx->ad_len += ad_len;
    if (left != 0) {
        if (left + ad_len < RATE) {
            memcpy(ctx->buf + left, ad, ad_len);
            return;
        }
        memcpy(ctx->buf + left, ad, RATE - left);
        aegis_128l_absorb(ctx->buf, st);
        ad += RATE - left;
        ad_len -= RATE - left;
    }
    for (i = 0; i + RATE * 2 <= ad_len; i += RATE * 2) {
        aes_block_t msg0, msg1, msg2, msg3;

        msg0 = AES_BLOCK_LOAD(ad + i + AES_BLOCK_LENGTH * 0);
        msg1 = AES_BLOCK_LOAD(ad + i + AES_BLOCK_LENGTH * 1);
        msg2 = AES_BLOCK_LOAD(ad + i + AES_BLOCK_LENGTH * 2);
        msg3 = AES_BLOCK_LOAD(ad + i + AES_BLOCK_LENGTH * 3);

        aegis_128l_update(st, msg0, msg1);
        aegis_128l_update(st, msg2, msg3);
    }
    for (; i + RATE <= ad_len; i += RATE) {
        aegis_128l_absorb(ad + i, st);
    }
    if (i < ad_len) {
        memset(ctx->buf, 0, RATE);
        memcpy(ctx->buf, ad + i, ad_len - i);
    }

    memcpy(ctx->state, st, sizeof st);
}

static void aegis_128l_enc(uint8_t * const dst, const uint8_t * const src,
                           aes_block_t * const state)
{
    aes_block_t msg0, msg1;
    aes_block_t tmp0, tmp1;

    msg0 = AES_BLOCK_LOAD(src);
    msg1 = AES_BLOCK_LOAD(src + AES_BLOCK_LENGTH);
    tmp0 = AES_BLOCK_XOR(msg0, state[6]);
    tmp0 = AES_BLOCK_XOR(tmp0, state[1]);
    tmp1 = AES_BLOCK_XOR(msg1, state[5]);
    tmp1 = AES_BLOCK_XOR(tmp1, state[2]);
    tmp0 = AES_BLOCK_XOR(tmp0, AES_BLOCK_AND(state[2], state[3]));
    tmp1 = AES_BLOCK_XOR(tmp1, AES_BLOCK_AND(state[6], state[7]));
    AES_BLOCK_STORE(dst, tmp0);
    AES_BLOCK_STORE(dst + AES_BLOCK_LENGTH, tmp1);

    aegis_128l_update(state, msg0, msg1);
}

static void aegis_128l_squeeze_keystream(uint8_t * const dst,
                                         aes_block_t * const state)
{
    aes_block_t tmp0, tmp1;

    tmp0 = AES_BLOCK_XOR(state[6], state[1]);
    tmp1 = AES_BLOCK_XOR(state[5], state[2]);
    tmp0 = AES_BLOCK_XOR(tmp0, AES_BLOCK_AND(state[2], state[3]));
    tmp1 = AES_BLOCK_XOR(tmp1, AES_BLOCK_AND(state[6], state[7]));
    AES_BLOCK_STORE(dst, tmp0);
    AES_BLOCK_STORE(dst + AES_BLOCK_LENGTH, tmp1);
}

static void aegis_128l_absorb_rate(const uint8_t * const src,
                                   aes_block_t * const state)
{
    aes_block_t msg0, msg1;

    msg0 = AES_BLOCK_LOAD(src);
    msg1 = AES_BLOCK_LOAD(src + AES_BLOCK_LENGTH);
    aegis_128l_update(state, msg0, msg1);
}

static void aegis_128l_dec(uint8_t * const dst, const uint8_t * const src,
                           aes_block_t * const state)
{
    aes_block_t msg0, msg1;

    msg0 = AES_BLOCK_LOAD(src);
    msg1 = AES_BLOCK_LOAD(src + AES_BLOCK_LENGTH);
    msg0 = AES_BLOCK_XOR(msg0, state[6]);
    msg0 = AES_BLOCK_XOR(msg0, state[1]);
    msg1 = AES_BLOCK_XOR(msg1, state[5]);
    msg1 = AES_BLOCK_XOR(msg1, state[2]);
    msg0 = AES_BLOCK_XOR(msg0, AES_BLOCK_AND(state[2], state[3]));
    msg1 = AES_BLOCK_XOR(msg1, AES_BLOCK_AND(state[6], state[7]));
    AES_BLOCK_STORE(dst, msg0);
    AES_BLOCK_STORE(dst + AES_BLOCK_LENGTH, msg1);

    aegis_128l_update(state, msg0, msg1);
}

static void aegis_128l_mac(uint8_t *mac, size_t maclen, size_t adlen,
                           size_t mlen, aes_block_t * const state)
{
    aes_block_t tmp;
    int i;

    tmp = AES_BLOCK_LOAD_64x2(((uint64_t)mlen) << 3, ((uint64_t)adlen) << 3);
    tmp = AES_BLOCK_XOR(tmp, state[2]);

    for (i = 0; i < 7; i++) {
        aegis_128l_update(state, tmp, tmp);
    }

    if (maclen == 16) {
        tmp = AES_BLOCK_XOR(state[6], AES_BLOCK_XOR(state[5], state[4]));
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[3], state[2]));
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[1], state[0]));
        AES_BLOCK_STORE(mac, tmp);
    } else if (maclen == 32) {
        tmp = AES_BLOCK_XOR(state[3], state[2]);
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[1], state[0]));
        AES_BLOCK_STORE(mac, tmp);
        tmp = AES_BLOCK_XOR(state[7], state[6]);
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[5], state[4]));
        AES_BLOCK_STORE(mac + 16, tmp);
    } else {
        memset(mac, 0, maclen);
    }
}

static int aegis_128l_encrypt_final(PROV_AEGIS_128L_CTX *ctx, size_t *written,
                                    uint8_t *c, uint8_t *mac, size_t maclen)
{
    aegis_128l_state state;

    memcpy(state, ctx->state, sizeof state);

    *written = 0;
    if (ctx->pos != 0) {
        memset(ctx->buf + ctx->pos, 0, sizeof ctx->buf - ctx->pos);
        aegis_128l_absorb_rate(ctx->buf, state);
        ctx->pos = 0;
    }
    aegis_128l_mac(mac, maclen, ctx->ad_len, ctx->msg_len, state);

    *written = maclen;

    memcpy(ctx->state, state, sizeof state);

    return 1;
}

static int aegis_128l_decrypt_final(PROV_AEGIS_128L_CTX *ctx, size_t *written,
                                    uint8_t *m, uint8_t *mac, size_t maclen)
{
    aegis_128l_state state;
    uint8_t computed_mac[32];
    int ret = 0;

    memcpy(state, ctx->state, sizeof state);

    *written = 0;
    if (ctx->pos != 0) {
        memset(ctx->buf + ctx->pos, 0, sizeof ctx->buf - ctx->pos);
        aegis_128l_absorb_rate(ctx->buf, state);
        ctx->pos = 0;
    }
    aegis_128l_mac(computed_mac, maclen, ctx->ad_len, ctx->msg_len, state);
    if (maclen <= sizeof computed_mac) {
        if (CRYPTO_memcmp(computed_mac, mac, maclen) == 0) {
            ret = 1;
            *written = ctx->pos;
        } else {
            memset(m, 0, ctx->pos);
        }
    }
    OPENSSL_cleanse(computed_mac, sizeof computed_mac);

    memcpy(ctx->state, state, sizeof state);

    return ret;
}

static int aegis_128l_encrypt_update(PROV_AEGIS_128L_CTX *ctx, size_t *written,
                                     uint8_t *c, const uint8_t *m, size_t mlen)
{
    aegis_128l_state state;
    size_t i = 0;
    size_t left;

    memcpy(state, ctx->state, sizeof state);

    *written = 0;
    ctx->msg_len += mlen;

    if (ctx->pos != 0) {
        const size_t available = (sizeof ctx->buf) - ctx->pos;
        const size_t n = mlen < available ? mlen : available;
        size_t j;
        uint8_t tmp;

        for (j = 0; j < n; j++) {
            tmp = m[i + j];
            c[j] = m[j] ^ ctx->buf[ctx->pos + j];
            ctx->buf[ctx->pos + j] = tmp;
        }
        if (ctx->pos < sizeof ctx->buf) {
            ctx->pos += n;
            *written = n;
            return 1;
        }
        aegis_128l_absorb_rate(ctx->buf, state);
        ctx->pos = 0;
    }
    for (i = 0; i + RATE <= mlen; i += RATE) {
        aegis_128l_enc(c + i, m + i, state);
    }
    left = mlen % RATE;
    if (left != 0) {
        size_t j;
        uint8_t tmp;

        aegis_128l_squeeze_keystream(ctx->buf, state);
        for (j = 0; j < left; j++) {
            tmp = m[i + j];
            c[i + j] = m[i + j] ^ ctx->buf[j];
            ctx->buf[j] = tmp;
        }
        ctx->pos = left;
    }
    *written = mlen;

    memcpy(ctx->state, state, sizeof state);

    return 1;
}

static int aegis_128l_decrypt_update(PROV_AEGIS_128L_CTX *ctx, size_t *written,
                                     uint8_t *m, const uint8_t *c, size_t clen)
{
    aegis_128l_state state;
    size_t i = 0;
    size_t left;

    memcpy(state, ctx->state, sizeof state);

    *written = 0;
    ctx->msg_len += clen;

    if (ctx->pos != 0) {
        const size_t available = (sizeof ctx->buf) - ctx->pos;
        const size_t n = clen < available ? clen : available;
        size_t j;

        for (j = 0; j < n; j++) {
            m[j] = c[j] ^ ctx->buf[ctx->pos + j];
            ctx->buf[ctx->pos + j] = m[j];
        }
        if (ctx->pos < sizeof ctx->buf) {
            ctx->pos += n;
            *written = n;
            return 1;
        }
        aegis_128l_absorb_rate(ctx->buf, state);
        ctx->pos = 0;
    }
    for (i = 0; i + RATE <= clen; i += RATE) {
        aegis_128l_dec(m + i, c + i, state);
    }
    left = clen % RATE;
    if (left != 0) {
        size_t j;

        aegis_128l_squeeze_keystream(ctx->buf, state);
        for (j = 0; j < left; j++) {
            m[i + j] = c[i + j] ^ ctx->buf[j];
            ctx->buf[j] = m[i + j];
        }
        ctx->pos = left;
    }
    *written = clen;

    memcpy(ctx->state, state, sizeof state);

    return 1;
}

static int aegis_128l_aead_cipher(PROV_CIPHER_CTX *bctx, unsigned char *out,
                                  size_t *outl, const unsigned char *in,
                                  size_t inl)
{
    PROV_AEGIS_128L_CTX * const ctx = (PROV_AEGIS_128L_CTX *)bctx;
    size_t written = 0;

    if (!bctx->key_set) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    if (outl != NULL) {
        *outl = 0;
    }
    if (out == NULL && in != NULL) {
        if (ctx->msg_len > 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_STATE);
            return 0;
        }
        aegis_128l_ad_update(ctx, in, inl);
        written = inl;
    } else if (out != NULL && in != NULL) {
        size_t left;

        left = ctx->ad_len % RATE;
        if (left != 0) {
            aegis_128l_state st;

            memset(ctx->buf + left, 0, RATE - left);
            memcpy(st, ctx->state, sizeof st);
            aegis_128l_absorb(ctx->buf, st);
            memcpy(ctx->state, st, sizeof ctx->state);
        }
        if (bctx->enc) {
            if (aegis_128l_encrypt_update(ctx, &written, out, in, inl) != 1) {
                return 0;
            }
        } else {
            if (aegis_128l_decrypt_update(ctx, &written, out, in, inl) != 1) {
                return 0;
            }
        }
    } else if (in == NULL) {
        if (bctx->enc) {
            if (aegis_128l_encrypt_final(ctx, &written, out, ctx->tag,
                                         ctx->tag_len)
                != 1) {
                return 0;
            }
        } else {
            if (aegis_128l_decrypt_final(ctx, &written, out, ctx->tag,
                                         ctx->tag_len)
                != 1) {
                return 0;
            }
        }
    } else {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_PARAMETERS);
        return 0;
    }
    if (outl != NULL) {
        *outl = written;
    }
    return 1;
}

static const PROV_CIPHER_HW_AEGIS_128L aegis_128l_hw = {
    {aegis_128l_initkey, NULL},
    aegis_128l_aead_cipher,
    aegis_128l_initiv,
    NULL,
    NULL,
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_aegis_128l(size_t keybits)
{
    return (PROV_CIPHER_HW *)&aegis_128l_hw;
}

# if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) \
     || defined(_M_ARM64)
#  ifdef __clang__
#   pragma clang attribute pop
#  endif
# endif

#endif
