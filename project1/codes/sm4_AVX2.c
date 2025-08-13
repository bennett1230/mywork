#include <immintrin.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

// ====================== 常量 ======================
static const uint32_t SM4_CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};
static const uint32_t SM4_FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

static const uint8_t SM4_SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

// ====================== 工具函数 ======================
static inline uint32_t rotl32(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}
static inline uint32_t load_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline void store_be32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

// 标量 S-box 作用于 32 位
static inline uint32_t sbox_word32(uint32_t x) {
    uint32_t b0 = SM4_SBOX[(x >> 24) & 0xFF];
    uint32_t b1 = SM4_SBOX[(x >> 16) & 0xFF];
    uint32_t b2 = SM4_SBOX[(x >> 8) & 0xFF];
    uint32_t b3 = SM4_SBOX[x & 0xFF];
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
}
static inline uint32_t L_scalar(uint32_t b) {
    return b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24);
}
static inline uint32_t Lp_scalar(uint32_t b) {
    return b ^ rotl32(b, 13) ^ rotl32(b, 23);
}
static inline uint32_t T_scalar(uint32_t x) { return L_scalar(sbox_word32(x)); }
static inline uint32_t Tp_scalar(uint32_t x) { return Lp_scalar(sbox_word32(x)); }

// ====================== 轮密钥扩展 ======================
static void sm4_key_expand(const uint8_t key[16], uint32_t rk_enc[32], uint32_t rk_dec[32]) {
    uint32_t MK[4], K[36];
    for (int i = 0; i < 4; i++) {
        MK[i] = load_be32(key + 4 * i);
    }
    for (int i = 0; i < 4; i++) {
        K[i] = MK[i] ^ SM4_FK[i];
    }
    for (int i = 0; i < 32; i++) {
        uint32_t t = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ SM4_CK[i];
        K[i + 4] = K[i] ^ Tp_scalar(t);
        rk_enc[i] = K[i + 4];
    }
    // 解密轮密钥是加密轮密钥的逆序
    for (int i = 0; i < 32; i++) {
        rk_dec[i] = rk_enc[31 - i];
    }
}

// ====================== AVX2 实现（8 块并行） ======================
static uint32_t SM4_SBOX32[256];
static int sm4_tables_ready = 0;
static void sm4_init_tables(void) {
    if (!sm4_tables_ready) {
        for (int i = 0; i < 256; i++) SM4_SBOX32[i] = SM4_SBOX[i];
        sm4_tables_ready = 1;
    }
}

static inline __m256i rotl32_avx2(__m256i x, int r) {
    return _mm256_or_si256(_mm256_slli_epi32(x, r), _mm256_srli_epi32(x, 32 - r));
}

static inline __m256i sbox_bytes_avx2(__m256i x) {
    const __m256i mask_ff = _mm256_set1_epi32(0xFF);
    __m256i i0 = _mm256_and_si256(x, mask_ff);
    __m256i i1 = _mm256_and_si256(_mm256_srli_epi32(x, 8), mask_ff);
    __m256i i2 = _mm256_and_si256(_mm256_srli_epi32(x, 16), mask_ff);
    __m256i i3 = _mm256_and_si256(_mm256_srli_epi32(x, 24), mask_ff);

    __m256i g0 = _mm256_i32gather_epi32((const int*)SM4_SBOX32, i0, 4);
    __m256i g1 = _mm256_i32gather_epi32((const int*)SM4_SBOX32, i1, 4);
    __m256i g2 = _mm256_i32gather_epi32((const int*)SM4_SBOX32, i2, 4);
    __m256i g3 = _mm256_i32gather_epi32((const int*)SM4_SBOX32, i3, 4);

    g1 = _mm256_slli_epi32(g1, 8);
    g2 = _mm256_slli_epi32(g2, 16);
    g3 = _mm256_slli_epi32(g3, 24);

    return _mm256_or_si256(_mm256_or_si256(g0, g1), _mm256_or_si256(g2, g3));
}

static inline __m256i T_avx2(__m256i x) {
    __m256i b = sbox_bytes_avx2(x);
    __m256i r2 = rotl32_avx2(b, 2);
    __m256i r10 = rotl32_avx2(b, 10);
    __m256i r18 = rotl32_avx2(b, 18);
    __m256i r24 = rotl32_avx2(b, 24);
    return _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(b, r2), r10), r18), r24);
}

static void sm4_crypt8_blocks_avx2(const uint8_t* in, uint8_t* out, const uint32_t rk[32], int is_decrypt) {
    sm4_init_tables();

    uint32_t x0[8], x1[8], x2[8], x3[8];
    for (int b = 0; b < 8; b++) {
        const uint8_t* p = in + 16 * b;
        x0[b] = load_be32(p + 0);
        x1[b] = load_be32(p + 4);
        x2[b] = load_be32(p + 8);
        x3[b] = load_be32(p + 12);
    }

    __m256i X0 = _mm256_loadu_si256((const __m256i*)x0);
    __m256i X1 = _mm256_loadu_si256((const __m256i*)x1);
    __m256i X2 = _mm256_loadu_si256((const __m256i*)x2);
    __m256i X3 = _mm256_loadu_si256((const __m256i*)x3);

    for (int r = 0; r < 32; r++) {
        __m256i t = _mm256_xor_si256(_mm256_xor_si256(X1, X2), X3);
        t = _mm256_xor_si256(t, _mm256_set1_epi32(rk[r]));
        __m256i tt = T_avx2(t);
        __m256i newX0 = _mm256_xor_si256(X0, tt);
        X0 = X1; X1 = X2; X2 = X3; X3 = newX0;
    }

    // 解密时需要反转输出顺序（与加密一致）
    _mm256_storeu_si256((__m256i*)x0, X3);
    _mm256_storeu_si256((__m256i*)x1, X2);
    _mm256_storeu_si256((__m256i*)x2, X1);
    _mm256_storeu_si256((__m256i*)x3, X0);

    for (int b = 0; b < 8; b++) {
        uint8_t* q = out + 16 * b;
        store_be32(q + 0, x0[b]);
        store_be32(q + 4, x1[b]);
        store_be32(q + 8, x2[b]);
        store_be32(q + 12, x3[b]);
    }
}

// 标量单块加密/解密
static void sm4_crypt_block_scalar(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32], int is_decrypt) {
    uint32_t X[4];
    X[0] = load_be32(in + 0);
    X[1] = load_be32(in + 4);
    X[2] = load_be32(in + 8);
    X[3] = load_be32(in + 12);

    for (int r = 0; r < 32; r++) {
        uint32_t t = X[1] ^ X[2] ^ X[3] ^ rk[r];
        uint32_t newX = X[0] ^ T_scalar(t);
        X[0] = X[1]; X[1] = X[2]; X[2] = X[3]; X[3] = newX;
    }

    store_be32(out + 0, X[3]);
    store_be32(out + 4, X[2]);
    store_be32(out + 8, X[1]);
    store_be32(out + 12, X[0]);
}

// ====================== 公共接口 ======================
void sm4_ecb_crypt_avx2(const uint8_t* in, uint8_t* out, size_t blocks, const uint8_t key[16], int is_decrypt) {
    uint32_t rk_enc[32], rk_dec[32];
    sm4_key_expand(key, rk_enc, rk_dec);
    const uint32_t* rk = is_decrypt ? rk_dec : rk_enc;

    size_t i = 0;
    for (; i + 8 <= blocks; i += 8) {
        sm4_crypt8_blocks_avx2(in + i * 16, out + i * 16, rk, is_decrypt);
    }
    for (; i < blocks; i++) {
        sm4_crypt_block_scalar(in + i * 16, out + i * 16, rk, is_decrypt);
    }
}

// ====================== 测试 ======================
int main(void) {
    // 标准测试向量
    const uint8_t key[16] = {
        0x01,0x23,0x45,0x67, 0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98, 0x76,0x54,0x32,0x10
    };
    const uint8_t pt[16] = {
        0x01,0x23,0x45,0x67, 0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98, 0x76,0x54,0x32,0x10
    };
    const uint8_t ct_expected[16] = {
        0x68,0x1e,0xdf,0x34, 0xd2,0x06,0x96,0x5e,
        0x86,0xb3,0xe9,0x4f, 0x53,0x6e,0x42,0x46
    };

    // 测试加密
    uint8_t ct[16];
    sm4_ecb_crypt_avx2(pt, ct, 1, key, 0);
    int ok = memcmp(ct, ct_expected, 16) == 0;
    printf("SM4 AVX2 ECB encrypt test: %s\n", ok ? "PASS" : "FAIL");

    // 测试解密
    uint8_t decrypted[16];
    sm4_ecb_crypt_avx2(ct, decrypted, 1, key, 1);
    ok &= memcmp(decrypted, pt, 16) == 0;
    printf("SM4 AVX2 ECB decrypt test: %s\n", ok ? "PASS" : "FAIL");

    // 打印结果
    if (ok) {
        printf("Plaintext:  ");
        for (int i = 0; i < 16; i++) printf("%02x", pt[i]);
        printf("\nCiphertext: ");
        for (int i = 0; i < 16; i++) printf("%02x", ct[i]);
        printf("\nDecrypted:  ");
        for (int i = 0; i < 16; i++) printf("%02x", decrypted[i]);
        printf("\n");
    }
    else {
        printf("Expected ciphertext: ");
        for (int i = 0; i < 16; i++) printf("%02x", ct_expected[i]);
        printf("\nActual ciphertext:  ");
        for (int i = 0; i < 16; i++) printf("%02x", ct[i]);
        printf("\n");
    }

    return ok ? 0 : 1;
}

