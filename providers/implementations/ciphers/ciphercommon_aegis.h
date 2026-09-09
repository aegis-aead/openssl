#include "internal/endian.h"
#include <string.h>

#define LOAD32_LE(SRC) load32_le(SRC)

static ossl_inline uint32_t load32_le(const uint8_t src[4])
{
#ifdef L_ENDIAN
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint32_t w = (uint32_t)src[0];
    w |= (uint32_t)src[1] << 8;
    w |= (uint32_t)src[2] << 16;
    w |= (uint32_t)src[3] << 24;
    return w;
#endif
}

#define STORE32_LE(DST, W) store32_le((DST), (W))

static ossl_inline void store32_le(uint8_t dst[4], uint32_t w)
{
#ifdef L_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t)w;
    w >>= 8;
    dst[1] = (uint8_t)w;
    w >>= 8;
    dst[2] = (uint8_t)w;
    w >>= 8;
    dst[3] = (uint8_t)w;
#endif
}

typedef struct softaes_block_t {
    uint32_t w0;
    uint32_t w1;
    uint32_t w2;
    uint32_t w3;
} softaes_block_t;

/*
 * The AES round is bitsliced, so that no memory access or branch depends on
 * secret data.
 * The state is held as eight 32-bit bit planes, plane 0 being the most
 * significant bit of every byte.
 * Row r of the state is byte r of a plane, with column c in bit c of that
 * byte, so that moving to the next row is a single 32-bit rotation.
 * The high nibble of every byte is unused: whatever it holds never mixes
 * with the low nibbles, and is masked out when unpacking.
 * ShiftRows is applied to the bytes before packing, SubBytes is the Boolean
 * circuit of libsodium's SRM-1R implementation, and MixColumns only needs
 * rotations and XORs.
 */

static ossl_inline uint32_t srm1r_ror32(uint32_t x, unsigned int n)
{
    return (x >> n) | (x << (32 - n));
}

static ossl_inline void srm1r_swap_move(uint32_t *a, uint32_t *b,
    uint32_t mask, unsigned int shift)
{
    const uint32_t t = ((*a >> shift) ^ *b) & mask;

    *b ^= t;
    *a ^= t << shift;
}

/*
 * Exchanges the index of each word with the two low bits of the bit
 * position in each byte, which makes this transformation its own inverse.
 * Given four column words, word k ends up with bit k of every byte in its
 * low nibbles and bit k + 4 in its high nibbles.
 * Row r stays in byte r, and column c lands in bit c of each nibble.
 */
static ossl_inline void srm1r_transpose(uint32_t w[4])
{
    srm1r_swap_move(&w[0], &w[1], 0x55555555, 1);
    srm1r_swap_move(&w[2], &w[3], 0x55555555, 1);
    srm1r_swap_move(&w[0], &w[2], 0x33333333, 2);
    srm1r_swap_move(&w[1], &w[3], 0x33333333, 2);
}

static ossl_inline void srm1r_pack(uint32_t planes[8],
    const softaes_block_t block)
{
    uint32_t w[4];

    /* ShiftRows: row r of column c comes from column (c + r) mod 4 */
    w[0] = (block.w0 & 0x000000ff) | (block.w1 & 0x0000ff00)
        | (block.w2 & 0x00ff0000) | (block.w3 & 0xff000000);
    w[1] = (block.w1 & 0x000000ff) | (block.w2 & 0x0000ff00)
        | (block.w3 & 0x00ff0000) | (block.w0 & 0xff000000);
    w[2] = (block.w2 & 0x000000ff) | (block.w3 & 0x0000ff00)
        | (block.w0 & 0x00ff0000) | (block.w1 & 0xff000000);
    w[3] = (block.w3 & 0x000000ff) | (block.w0 & 0x0000ff00)
        | (block.w1 & 0x00ff0000) | (block.w2 & 0xff000000);
    srm1r_transpose(w);

    planes[0] = w[3] >> 4;
    planes[1] = w[2] >> 4;
    planes[2] = w[1] >> 4;
    planes[3] = w[0] >> 4;
    planes[4] = w[3];
    planes[5] = w[2];
    planes[6] = w[1];
    planes[7] = w[0];
}

static ossl_inline void srm1r_unpack(uint32_t w[4], const uint32_t planes[8])
{
    w[0] = (planes[7] & 0x0f0f0f0f) | ((planes[3] & 0x0f0f0f0f) << 4);
    w[1] = (planes[6] & 0x0f0f0f0f) | ((planes[2] & 0x0f0f0f0f) << 4);
    w[2] = (planes[5] & 0x0f0f0f0f) | ((planes[1] & 0x0f0f0f0f) << 4);
    w[3] = (planes[4] & 0x0f0f0f0f) | ((planes[0] & 0x0f0f0f0f) << 4);
    srm1r_transpose(w);
}

static ossl_inline void srm1r_sub_bytes(uint32_t planes[8])
{
    const uint32_t s0 = planes[1] ^ planes[4];
    const uint32_t s1 = planes[5] ^ planes[7];
    const uint32_t s2 = planes[3] ^ s0;
    const uint32_t s3 = planes[0] ^ planes[2];
    const uint32_t s4 = planes[0] ^ planes[6];
    const uint32_t s5 = planes[2] ^ planes[6];
    const uint32_t s6 = planes[3] ^ s1;
    const uint32_t s7 = planes[5] ^ s3;
    const uint32_t s8 = planes[4] ^ s3;
    const uint32_t s9 = planes[6] ^ s0;
    const uint32_t q0 = s1 ^ s2;
    const uint32_t q1 = s1 ^ s5;
    const uint32_t q2 = planes[2] ^ q0;
    const uint32_t q3 = s4 ^ s2;
    const uint32_t q4 = s3 ^ q0;
    const uint32_t q5 = s6 ^ s8;
    const uint32_t q6 = planes[2] ^ planes[3];
    const uint32_t q7 = planes[6] ^ s2;
    const uint32_t q8 = s3 ^ s9;
    const uint32_t q9 = s4 ^ s6;
    const uint32_t q10 = s0 ^ s5;
    const uint32_t q11 = planes[5];
    const uint32_t q12 = planes[7] ^ s2;
    const uint32_t q13 = planes[1] ^ s7;
    const uint32_t q14 = planes[7] ^ s3;
    const uint32_t q15 = s2 ^ s7;
    const uint32_t q16 = planes[1] ^ s1;
    const uint32_t q17 = planes[1] ^ planes[7];

    const uint32_t t20 = q6 & q12;
    const uint32_t t21 = q3 & q14;
    const uint32_t t22 = q1 & q16;
    const uint32_t t23 = q2 & q17;
    const uint32_t x0 = ((q3 | q14) ^ (q0 & q7)) ^ (t20 ^ t22);
    const uint32_t x1 = ((q4 | q13) ^ (q10 & q11)) ^ (t21 ^ t20);
    const uint32_t x2 = ((q2 | q17) ^ (q5 & q9)) ^ (t21 ^ t22);
    const uint32_t x3 = ((q8 | q15) ^ t23) ^ (t21 ^ (q4 & q13));

    const uint32_t a = x1 & ~x3;
    const uint32_t b = x0 & ~x3;
    const uint32_t c = x3 & ~x1;
    const uint32_t d = x2 & ~x1;
    const uint32_t e = x0 ^ a;
    const uint32_t f = x1 ^ b;
    const uint32_t g = x2 ^ c;
    const uint32_t h = x3 ^ d;
    const uint32_t y0 = x3 ^ (x2 & ~e);
    const uint32_t y1 = c ^ (x2 & f);
    const uint32_t y2 = x1 ^ (x0 & ~g);
    const uint32_t y3 = a ^ (x0 & h);
    const uint32_t y02 = y2 ^ y0;
    const uint32_t y13 = y3 ^ y1;
    const uint32_t y23 = y3 ^ y2;
    const uint32_t y01 = y1 ^ y0;
    const uint32_t y00 = y02 ^ y13;

    const uint32_t a0 = y01 & q11;
    const uint32_t a1 = y0 & q12;
    const uint32_t a2 = y1 & q0;
    const uint32_t a3 = y23 & q17;
    const uint32_t a4 = y2 & q5;
    const uint32_t a5 = y3 & q15;
    const uint32_t a6 = y13 & q14;
    const uint32_t a7 = y00 & q16;
    const uint32_t a8 = y02 & q13;
    const uint32_t a9 = y01 & q7;
    const uint32_t a10 = y0 & q10;
    const uint32_t a11 = y1 & q6;
    const uint32_t a12 = y23 & q2;
    const uint32_t a13 = y2 & q9;
    const uint32_t a14 = y3 & q8;
    const uint32_t a15 = y13 & q3;
    const uint32_t a16 = y00 & q1;
    const uint32_t a17 = y02 & q4;

    const uint32_t r0 = a1 ^ a5;
    const uint32_t r1 = a9 ^ a15;
    const uint32_t r2 = a4 ^ r0;
    const uint32_t r3 = a2 ^ a10;
    const uint32_t r4 = a11 ^ a17;
    const uint32_t r5 = a8 ^ r1;
    const uint32_t r6 = a0 ^ a16;
    const uint32_t r7 = a7 ^ a13;
    const uint32_t r8 = a11 ^ a14;
    const uint32_t r9 = r3 ^ r4;
    const uint32_t r10 = r5 ^ r6;
    const uint32_t r11 = r2 ^ r9;
    const uint32_t r12 = a3 ^ r0;
    const uint32_t r13 = r7 ^ r8;
    const uint32_t r14 = r12 ^ r13;
    const uint32_t r15 = a6 ^ a10;
    const uint32_t r16 = r15 ^ r2;
    const uint32_t r17 = a12 ^ a13;
    const uint32_t r18 = a15 ^ r17;
    const uint32_t r19 = a1 ^ a14;
    const uint32_t r20 = a17 ^ r3;
    const uint32_t r21 = r7 ^ r19;
    const uint32_t r22 = r5 ^ r20;
    const uint32_t r23 = a9 ^ a12;

    /* The complemented planes add the 0x63 constant of the affine map */
    planes[0] = r10 ^ r14;
    planes[1] = ~(r10 ^ r16);
    planes[2] = ~(a2 ^ r2);
    planes[3] = r18 ^ r11;
    planes[4] = r21 ^ r22;
    planes[5] = r8 ^ r23;
    planes[6] = ~(r1 ^ r4);
    planes[7] = ~(a16 ^ r11);
}

/*
 * Row r of a column s becomes 2 * (s[r] ^ s[r + 1]) ^ s[r + 1] ^ s[r + 2] ^
 * s[r + 3] in GF(2^8), with row indices taken modulo 4.
 * Rotating a plane right by 8 bits lines every row up with the next one.
 */
static ossl_inline void srm1r_mix_columns(uint32_t planes[8])
{
    const uint32_t adj0 = srm1r_ror32(planes[0], 8);
    const uint32_t adj1 = srm1r_ror32(planes[1], 8);
    const uint32_t adj2 = srm1r_ror32(planes[2], 8);
    const uint32_t adj3 = srm1r_ror32(planes[3], 8);
    const uint32_t adj4 = srm1r_ror32(planes[4], 8);
    const uint32_t adj5 = srm1r_ror32(planes[5], 8);
    const uint32_t adj6 = srm1r_ror32(planes[6], 8);
    const uint32_t adj7 = srm1r_ror32(planes[7], 8);
    const uint32_t pair0 = planes[0] ^ adj0;
    const uint32_t pair1 = planes[1] ^ adj1;
    const uint32_t pair2 = planes[2] ^ adj2;
    const uint32_t pair3 = planes[3] ^ adj3;
    const uint32_t pair4 = planes[4] ^ adj4;
    const uint32_t pair5 = planes[5] ^ adj5;
    const uint32_t pair6 = planes[6] ^ adj6;
    const uint32_t pair7 = planes[7] ^ adj7;
    const uint32_t opp0 = srm1r_ror32(pair0, 16);
    const uint32_t opp1 = srm1r_ror32(pair1, 16);
    const uint32_t opp2 = srm1r_ror32(pair2, 16);
    const uint32_t opp3 = srm1r_ror32(pair3, 16);
    const uint32_t opp4 = srm1r_ror32(pair4, 16);
    const uint32_t opp5 = srm1r_ror32(pair5, 16);
    const uint32_t opp6 = srm1r_ror32(pair6, 16);
    const uint32_t opp7 = srm1r_ror32(pair7, 16);

    planes[0] = pair1 ^ adj0 ^ opp0;
    planes[1] = pair2 ^ adj1 ^ opp1;
    planes[2] = pair3 ^ adj2 ^ opp2;
    planes[3] = pair4 ^ adj3 ^ opp3 ^ pair0;
    planes[4] = pair5 ^ adj4 ^ opp4 ^ pair0;
    planes[5] = pair6 ^ adj5 ^ opp5;
    planes[6] = pair7 ^ adj6 ^ opp6 ^ pair0;
    planes[7] = pair0 ^ adj7 ^ opp7;
}

static ossl_inline softaes_block_t
softaes_block_encrypt(const softaes_block_t block, const softaes_block_t rk)
{
    softaes_block_t out;
    uint32_t planes[8];
    uint32_t w[4];

    srm1r_pack(planes, block);
    srm1r_sub_bytes(planes);
    srm1r_mix_columns(planes);
    srm1r_unpack(w, planes);

    out.w0 = w[0] ^ rk.w0;
    out.w1 = w[1] ^ rk.w1;
    out.w2 = w[2] ^ rk.w2;
    out.w3 = w[3] ^ rk.w3;

    return out;
}

static ossl_inline softaes_block_t softaes_block_load(const uint8_t in[16])
{
#ifdef NATIVE_LITTLE_ENDIAN
    softaes_block_t out;
    memcpy(&out, in, 16);
#else
    const softaes_block_t out = { LOAD32_LE(in + 0), LOAD32_LE(in + 4),
        LOAD32_LE(in + 8), LOAD32_LE(in + 12) };
#endif
    return out;
}

static ossl_inline softaes_block_t softaes_block_load64x2(const uint64_t a,
    const uint64_t b)
{
    const softaes_block_t out = { (uint32_t)b, (uint32_t)(b >> 32), (uint32_t)a,
        (uint32_t)(a >> 32) };
    return out;
}

static ossl_inline void softaes_block_store(uint8_t out[16],
    const softaes_block_t in)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(out, &in, 16);
#else
    STORE32_LE(out + 0, in.w0);
    STORE32_LE(out + 4, in.w1);
    STORE32_LE(out + 8, in.w2);
    STORE32_LE(out + 12, in.w3);
#endif
}

static ossl_inline softaes_block_t softaes_block_xor(const softaes_block_t a,
    const softaes_block_t b)
{
    const softaes_block_t out = { a.w0 ^ b.w0, a.w1 ^ b.w1, a.w2 ^ b.w2,
        a.w3 ^ b.w3 };
    return out;
}

static ossl_inline softaes_block_t softaes_block_and(const softaes_block_t a,
    const softaes_block_t b)
{
    const softaes_block_t out = { a.w0 & b.w0, a.w1 & b.w1, a.w2 & b.w2,
        a.w3 & b.w3 };
    return out;
}
