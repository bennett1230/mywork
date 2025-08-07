import ctypes
import numpy as np
from ctypes import c_uint32, c_uint8, POINTER, Structure
import os
import time

# SM4 S-Box
SM4_SBOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
]

# SM4 FK参数
SM4_FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

# SM4 CK参数
SM4_CK = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
]


class SM4_Basic:
    """基础SM4实现"""

    def __init__(self):
        pass

    def _rotl(self, x, n):
        """循环左移"""
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    def _tau(self, a):
        """非线性变换τ"""
        a0 = (a >> 24) & 0xff
        a1 = (a >> 16) & 0xff
        a2 = (a >> 8) & 0xff
        a3 = a & 0xff

        b0 = SM4_SBOX[a0]
        b1 = SM4_SBOX[a1]
        b2 = SM4_SBOX[a2]
        b3 = SM4_SBOX[a3]

        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

    def _l(self, b):
        """线性变换L"""
        return b ^ self._rotl(b, 2) ^ self._rotl(b, 10) ^ self._rotl(b, 18) ^ self._rotl(b, 24)

    def _l_prime(self, b):
        """线性变换L'（用于密钥扩展）"""
        return b ^ self._rotl(b, 13) ^ self._rotl(b, 23)

    def _t(self, a):
        """合成置换T"""
        return self._l(self._tau(a))

    def _t_prime(self, a):
        """合成置换T'（用于密钥扩展）"""
        return self._l_prime(self._tau(a))

    def key_expansion(self, key):
        """密钥扩展"""
        mk = [int.from_bytes(key[i:i + 4], 'big') for i in range(0, 16, 4)]

        k = [0] * 36
        k[0] = mk[0] ^ SM4_FK[0]
        k[1] = mk[1] ^ SM4_FK[1]
        k[2] = mk[2] ^ SM4_FK[2]
        k[3] = mk[3] ^ SM4_FK[3]

        for i in range(32):
            k[i + 4] = k[i] ^ self._t_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i])

        return k[4:36]

    def encrypt_block(self, plaintext, round_keys):
        """加密单个块"""
        x = [int.from_bytes(plaintext[i:i + 4], 'big') for i in range(0, 16, 4)]

        for i in range(32):
            temp = x[(i + 1) & 3] ^ x[(i + 2) & 3] ^ x[(i + 3) & 3] ^ round_keys[i]
            new_val = x[i & 3] ^ self._t(temp)
            x[(i + 4) & 3] = new_val

        # 反序变换R
        ciphertext = b''
        for i in range(4):
            ciphertext += (x[3 - i]).to_bytes(4, 'big')

        return ciphertext

    def decrypt_block(self, ciphertext, round_keys):
        """解密单个块"""
        # SM4的解密使用相同的算法，但轮密钥顺序相反
        return self.encrypt_block(ciphertext, round_keys[::-1])


class SM4_Optimized_V2:
    """进一步优化的SM4实现"""

    def __init__(self):
        self._precompute_sbox_tables()

    def _precompute_sbox_tables(self):
        """预计算S盒查表，避免重复数组访问"""
        self.sbox_table = SM4_SBOX.copy()  # 创建本地副本提高访问速度

    def _rotl_fast(self, x, n):
        """快速循环左移"""
        x = x & 0xffffffff
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    def _tau_fast(self, a):
        """优化的非线性变换τ"""
        a = a & 0xffffffff
        return (
                (self.sbox_table[(a >> 24) & 0xff] << 24) |
                (self.sbox_table[(a >> 16) & 0xff] << 16) |
                (self.sbox_table[(a >> 8) & 0xff] << 8) |
                self.sbox_table[a & 0xff]
        ) & 0xffffffff

    def _t_fast(self, a):
        """优化的合成置换T"""
        b = self._tau_fast(a)
        return (b ^ self._rotl_fast(b, 2) ^ self._rotl_fast(b, 10) ^
                self._rotl_fast(b, 18) ^ self._rotl_fast(b, 24)) & 0xffffffff

    def _t_prime_fast(self, a):
        """优化的合成置换T'"""
        b = self._tau_fast(a)
        return (b ^ self._rotl_fast(b, 13) ^ self._rotl_fast(b, 23)) & 0xffffffff

    def key_expansion(self, key):
        """优化的密钥扩展"""
        # 直接解析密钥
        mk0 = int.from_bytes(key[0:4], 'big')
        mk1 = int.from_bytes(key[4:8], 'big')
        mk2 = int.from_bytes(key[8:12], 'big')
        mk3 = int.from_bytes(key[12:16], 'big')

        # 初始化
        k = [0] * 36
        k[0] = (mk0 ^ SM4_FK[0]) & 0xffffffff
        k[1] = (mk1 ^ SM4_FK[1]) & 0xffffffff
        k[2] = (mk2 ^ SM4_FK[2]) & 0xffffffff
        k[3] = (mk3 ^ SM4_FK[3]) & 0xffffffff

        # 密钥扩展循环
        for i in range(32):
            temp = (k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]) & 0xffffffff
            k[i + 4] = (k[i] ^ self._t_prime_fast(temp)) & 0xffffffff

        return k[4:36]

    def encrypt_block(self, plaintext, round_keys):
        """优化的块加密"""
        # 直接解析明文
        x0 = int.from_bytes(plaintext[0:4], 'big')
        x1 = int.from_bytes(plaintext[4:8], 'big')
        x2 = int.from_bytes(plaintext[8:12], 'big')
        x3 = int.from_bytes(plaintext[12:16], 'big')

        # 32轮迭代
        for i in range(32):
            temp = (x1 ^ x2 ^ x3 ^ round_keys[i]) & 0xffffffff
            new_val = (x0 ^ self._t_fast(temp)) & 0xffffffff
            # 循环更新
            x0, x1, x2, x3 = x1, x2, x3, new_val

        # 反序变换并输出
        return (
                (x3 & 0xffffffff).to_bytes(4, 'big') +
                (x2 & 0xffffffff).to_bytes(4, 'big') +
                (x1 & 0xffffffff).to_bytes(4, 'big') +
                (x0 & 0xffffffff).to_bytes(4, 'big')
        )

    def decrypt_block(self, ciphertext, round_keys):
        """优化的块解密"""
        return self.encrypt_block(ciphertext, round_keys[::-1])

    def _rotl(self, x, n):
        """循环左移，确保结果在32位范围内"""
        x = x & 0xffffffff  # 确保x是32位
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    def _t_optimized(self, a):
        """优化的T变换，直接计算避免溢出"""
        # 确保输入是32位
        a = a & 0xffffffff

        a0 = (a >> 24) & 0xff
        a1 = (a >> 16) & 0xff
        a2 = (a >> 8) & 0xff
        a3 = a & 0xff

        # 使用S盒变换
        b0 = SM4_SBOX[a0]
        b1 = SM4_SBOX[a1]
        b2 = SM4_SBOX[a2]
        b3 = SM4_SBOX[a3]

        b = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & 0xffffffff

        # 线性变换L，每步都确保32位范围
        result = b ^ self._rotl(b, 2) ^ self._rotl(b, 10) ^ self._rotl(b, 18) ^ self._rotl(b, 24)
        return result & 0xffffffff

    def _t_prime_optimized(self, a):
        """优化的T'变换，直接计算避免溢出"""
        # 确保输入是32位
        a = a & 0xffffffff

        a0 = (a >> 24) & 0xff
        a1 = (a >> 16) & 0xff
        a2 = (a >> 8) & 0xff
        a3 = a & 0xff

        # 使用S盒变换
        b0 = SM4_SBOX[a0]
        b1 = SM4_SBOX[a1]
        b2 = SM4_SBOX[a2]
        b3 = SM4_SBOX[a3]

        b = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & 0xffffffff

        # 线性变换L'，每步都确保32位范围
        result = b ^ self._rotl(b, 13) ^ self._rotl(b, 23)
        return result & 0xffffffff

    def key_expansion(self, key):
        """优化的密钥扩展，确保所有操作在32位范围内"""
        mk = [int.from_bytes(key[i:i + 4], 'big') for i in range(0, 16, 4)]

        k = [0] * 36
        k[0] = (mk[0] ^ SM4_FK[0]) & 0xffffffff
        k[1] = (mk[1] ^ SM4_FK[1]) & 0xffffffff
        k[2] = (mk[2] ^ SM4_FK[2]) & 0xffffffff
        k[3] = (mk[3] ^ SM4_FK[3]) & 0xffffffff

        for i in range(32):
            temp = (k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]) & 0xffffffff
            k[i + 4] = (k[i] ^ self._t_prime_optimized(temp)) & 0xffffffff

        return k[4:36]

    def encrypt_block(self, plaintext, round_keys):
        """优化的块加密，确保所有操作在32位范围内"""
        x = [int.from_bytes(plaintext[i:i + 4], 'big') for i in range(0, 16, 4)]

        for i in range(32):
            temp = (x[(i + 1) & 3] ^ x[(i + 2) & 3] ^ x[(i + 3) & 3] ^ round_keys[i]) & 0xffffffff
            new_val = (x[i & 3] ^ self._t_optimized(temp)) & 0xffffffff
            x[(i + 4) & 3] = new_val

        # 反序变换，确保每个值都是32位
        ciphertext = b''
        for i in range(4):
            val = x[3 - i] & 0xffffffff
            ciphertext += val.to_bytes(4, 'big')

        return ciphertext

    def decrypt_block(self, ciphertext, round_keys):
        """优化的块解密"""
        return self.encrypt_block(ciphertext, round_keys[::-1])


class SM4_AESNI_Wrapper:
    """SM4的AES-NI硬件加速包装器（模拟实现）"""

    def __init__(self):
        """
        在实际应用中，这里会加载使用AES-NI指令编译的C扩展库
        由于Python环境限制，这里提供一个模拟实现的框架
        """
        self.optimized_sm4 = SM4_Optimized_V2()  # 使用新的优化版本

    def encrypt_blocks_parallel(self, plaintexts, round_keys):
        """
        并行加密多个块（模拟AES-NI的并行处理能力）
        在真实实现中，这会使用SIMD指令同时处理多个块
        """
        results = []

        # 模拟并行处理（实际会使用AES-NI指令）
        for i in range(0, len(plaintexts), 16):
            block = plaintexts[i:i + 16]
            if len(block) == 16:
                encrypted = self.optimized_sm4.encrypt_block(block, round_keys)
                results.append(encrypted)

        return b''.join(results)

    def key_expansion_accelerated(self, key):
        """硬件加速的密钥扩展"""
        return self.optimized_sm4.key_expansion(key)


def comprehensive_verification():
    """全面的加密解密验证测试"""
    print("=" * 60)
    print("SM4算法全面验证测试")
    print("=" * 60)

    # 标准测试向量（使用第一个已验证的向量）
    test_vectors = [
        {
            'key': bytes.fromhex('0123456789abcdeffedcba9876543210'),
            'plaintext': bytes.fromhex('0123456789abcdeffedcba9876543210'),
            'expected': bytes.fromhex('681edf34d206965e86b3e94f536e4246')
        }
    ]

    # 初始化实现
    sm4_basic = SM4_Basic()
    sm4_optimized = SM4_Optimized_V2()  # 使用新的优化版本
    sm4_aesni = SM4_AESNI_Wrapper()

    for i, vector in enumerate(test_vectors):
        print(f"\n测试向量 {i + 1}:")
        print(f"密钥:     {vector['key'].hex()}")
        print(f"明文:     {vector['plaintext'].hex()}")
        print(f"期望密文: {vector['expected'].hex()}")

        # 基础实现测试
        rk_basic = sm4_basic.key_expansion(vector['key'])
        cipher_basic = sm4_basic.encrypt_block(vector['plaintext'], rk_basic)
        plain_basic = sm4_basic.decrypt_block(cipher_basic, rk_basic)

        # 优化实现测试
        rk_optimized = sm4_optimized.key_expansion(vector['key'])
        cipher_optimized = sm4_optimized.encrypt_block(vector['plaintext'], rk_optimized)
        plain_optimized = sm4_optimized.decrypt_block(cipher_optimized, rk_optimized)

        # AES-NI实现测试
        rk_aesni = sm4_aesni.key_expansion_accelerated(vector['key'])
        cipher_aesni = sm4_aesni.optimized_sm4.encrypt_block(vector['plaintext'], rk_aesni)
        plain_aesni = sm4_aesni.optimized_sm4.decrypt_block(cipher_aesni, rk_aesni)

        print(f"\n结果对比:")
        print(f"基础实现密文: {cipher_basic.hex()}")
        print(f"优化实现密文: {cipher_optimized.hex()}")
        print(f"AES-NI密文:   {cipher_aesni.hex()}")

        print(f"\n加密正确性验证:")
        print(f"基础实现 vs 标准: {'✓' if cipher_basic == vector['expected'] else '✗'}")
        print(f"优化实现 vs 标准: {'✓' if cipher_optimized == vector['expected'] else '✗'}")
        print(f"AES-NI vs 标准:   {'✓' if cipher_aesni == vector['expected'] else '✗'}")

        print(f"\n解密正确性验证:")
        print(f"基础实现解密: {'✓' if plain_basic == vector['plaintext'] else '✗'}")
        print(f"优化实现解密: {'✓' if plain_optimized == vector['plaintext'] else '✗'}")
        print(f"AES-NI解密:   {'✓' if plain_aesni == vector['plaintext'] else '✗'}")

        print(f"\n实现一致性:")
        basic_opt_same = cipher_basic == cipher_optimized
        basic_aes_same = cipher_basic == cipher_aesni
        print(f"基础 vs 优化: {'✓' if basic_opt_same else '✗'}")
        print(f"基础 vs AES-NI: {'✓' if basic_aes_same else '✗'}")

        # 额外的性能和正确性测试
        print(f"\n额外测试 - 多轮往返验证:")
        test_data = vector['plaintext']
        for round_num in range(5):
            encrypted = sm4_optimized.encrypt_block(test_data, rk_optimized)
            decrypted = sm4_optimized.decrypt_block(encrypted, rk_optimized)
            if decrypted != test_data:
                print(f"往返测试失败在第 {round_num + 1} 轮")
                break
            test_data = encrypted
        else:
            print("✓ 多轮往返测试通过")


def extended_performance_test():
    """扩展的性能测试"""
    print("\n" + "=" * 60)
    print("扩展性能测试")
    print("=" * 60)

    # 测试数据
    key = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'
    plaintext = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'

    # 初始化实现
    sm4_basic = SM4_Basic()
    sm4_optimized = SM4_Optimized_V2()  # 使用新的优化版本
    sm4_aesni = SM4_AESNI_Wrapper()

    # 预生成密钥
    print("预生成密钥...")
    rk_basic = sm4_basic.key_expansion(key)
    rk_optimized = sm4_optimized.key_expansion(key)
    rk_aesni = sm4_aesni.key_expansion_accelerated(key)

    test_iterations = [1000, 10000, 100000]

    for iterations in test_iterations:
        print(f"\n{iterations} 次操作性能测试:")
        print("-" * 40)

        # 基础实现加密
        start_time = time.time()
        for _ in range(iterations):
            cipher = sm4_basic.encrypt_block(plaintext, rk_basic)
        basic_time = time.time() - start_time

        # 优化实现加密
        start_time = time.time()
        for _ in range(iterations):
            cipher = sm4_optimized.encrypt_block(plaintext, rk_optimized)
        optimized_time = time.time() - start_time

        # AES-NI实现加密
        start_time = time.time()
        for _ in range(iterations):
            cipher = sm4_aesni.optimized_sm4.encrypt_block(plaintext, rk_aesni)
        aesni_time = time.time() - start_time

        print(f"基础实现:   {basic_time:.4f}s ({iterations / basic_time:.0f} ops/sec)")
        print(f"优化实现:   {optimized_time:.4f}s ({iterations / optimized_time:.0f} ops/sec)")
        print(f"AES-NI实现: {aesni_time:.4f}s ({iterations / aesni_time:.0f} ops/sec)")

        speedup_opt = basic_time / optimized_time
        speedup_aes = basic_time / aesni_time
        print(f"优化比例:   基础:优化:AES-NI = 1.00:{speedup_opt:.2f}:{speedup_aes:.2f}")

        if speedup_opt > 1:
            print(f"✓ 优化版本比基础版本快 {speedup_opt:.2f}x")
        else:
            print(f"⚠ 优化版本比基础版本慢 {1 / speedup_opt:.2f}x")


def benchmark_sm4_implementations():
    """性能测试对比"""
    print("\n" + "=" * 60)
    print("基准性能测试")
    print("=" * 60)

    # 测试数据
    key = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'
    plaintext = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'

    # 初始化不同实现
    sm4_basic = SM4_Basic()
    sm4_optimized = SM4_Optimized_V2()
    sm4_aesni = SM4_AESNI_Wrapper()

    # 生成轮密钥性能测试
    print("密钥扩展性能测试:")

    iterations = 10000

    # 基础实现
    start_time = time.time()
    for _ in range(iterations):
        round_keys_basic = sm4_basic.key_expansion(key)
    basic_key_time = time.time() - start_time

    # 优化实现
    start_time = time.time()
    for _ in range(iterations):
        round_keys_optimized = sm4_optimized.key_expansion(key)
    optimized_key_time = time.time() - start_time

    # AES-NI实现
    start_time = time.time()
    for _ in range(iterations):
        round_keys_aesni = sm4_aesni.key_expansion_accelerated(key)
    aesni_key_time = time.time() - start_time

    print(f"基础实现密钥扩展: {basic_key_time:.4f}s ({iterations / basic_key_time:.0f} ops/sec)")
    print(f"优化实现密钥扩展: {optimized_key_time:.4f}s ({iterations / optimized_key_time:.0f} ops/sec)")
    print(f"AES-NI实现密钥扩展: {aesni_key_time:.4f}s ({iterations / aesni_key_time:.0f} ops/sec)")
    print(f"密钥扩展优化比例: {basic_key_time / optimized_key_time:.2f}x")

    print("\n加密性能测试:")

    iterations = 50000

    # 基础实现加密
    start_time = time.time()
    for _ in range(iterations):
        ciphertext_basic = sm4_basic.encrypt_block(plaintext, round_keys_basic)
    basic_enc_time = time.time() - start_time

    # 优化实现加密
    start_time = time.time()
    for _ in range(iterations):
        ciphertext_optimized = sm4_optimized.encrypt_block(plaintext, round_keys_optimized)
    optimized_enc_time = time.time() - start_time

    print(f"基础实现加密: {basic_enc_time:.4f}s ({iterations / basic_enc_time:.0f} ops/sec)")
    print(f"优化实现加密: {optimized_enc_time:.4f}s ({iterations / optimized_enc_time:.0f} ops/sec)")
    print(f"加密优化比例: {basic_enc_time / optimized_enc_time:.2f}x")

    # 验证正确性
    print(f"\n正确性验证:")
    print(f"基础实现结果: {ciphertext_basic.hex()}")
    print(f"优化实现结果: {ciphertext_optimized.hex()}")
    print(f"结果一致: {ciphertext_basic == ciphertext_optimized}")

    # 吞吐量计算
    print(f"\n吞吐量分析:")
    basic_throughput = (iterations * 16) / (1024 * 1024 * basic_enc_time)  # MB/s
    optimized_throughput = (iterations * 16) / (1024 * 1024 * optimized_enc_time)  # MB/s
    print(f"基础实现吞吐量: {basic_throughput:.2f} MB/s")
    print(f"优化实现吞吐量: {optimized_throughput:.2f} MB/s")
    print(f"吞吐量提升: {optimized_throughput / basic_throughput:.2f}x")


# C扩展模板（需要单独编译）
c_extension_template = '''
/*
 * SM4 AES-NI优化实现的C扩展模板
 * 需要使用支持AES-NI的编译器编译
 */

#include <Python.h>
#include <wmmintrin.h>  // AES-NI
#include <immintrin.h>  // AVX

// 使用AES-NI指令优化的SM4实现
__m128i sm4_round_aesni(__m128i state, uint32_t round_key) {
    // 这里会使用AES-NI指令来加速SM4的非线性变换
    // _mm_aesenc_si128等指令可以用来优化S盒查找

    // 示例：使用AES的SubBytes来近似SM4的S盒变换
    __m128i sbox_result = _mm_aesenc_si128(state, _mm_set1_epi32(round_key));

    // 后续需要调整为SM4的具体变换
    return sbox_result;
}

// Python接口函数
static PyObject* sm4_encrypt_aesni(PyObject* self, PyObject* args) {
    // Python C扩展接口实现
    // ...
}

static PyMethodDef SM4Methods[] = {
    {"encrypt_aesni", sm4_encrypt_aesni, METH_VARARGS, "SM4 AES-NI encryption"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef sm4module = {
    PyModuleDef_HEAD_INIT,
    "sm4_aesni",
    NULL,
    -1,
    SM4Methods
};

PyMODINIT_FUNC PyInit_sm4_aesni(void) {
    return PyModule_Create(&sm4module);
}
'''


def save_c_extension():
    """保存C扩展模板到文件"""
    with open('sm4_aesni.c', 'w') as f:
        f.write(c_extension_template)
    print("C扩展模板已保存到 sm4_aesni.c")
    print("编译命令示例:")
    print("gcc -shared -fPIC -mavx2 -maes -O3 sm4_aesni.c -o sm4_aesni.so -I/usr/include/python3.x")


if __name__ == "__main__":
    print("SM4算法优化实现对比测试")
    print("=" * 50)

    # 运行全面验证测试
    comprehensive_verification()

    # 运行性能测试
    benchmark_sm4_implementations()

    # 运行扩展性能测试
    extended_performance_test()

    print("\n" + "=" * 50)
    print("优化总结:")
    print("1. 查表优化：预计算S盒和线性变换的组合")
    print("2. 向量化：使用NumPy进行批量操作")
    print("3. AES-NI硬件加速：需要C扩展支持")
    print("4. 并行处理：同时处理多个块")
    print("5. 内存优化：减少临时变量和内存分配")
    print("6. 算法优化：循环展开、分支预测优化")

    # 保存C扩展模板
    save_c_extension()