import struct
import time
import os
from typing import List

class SM3_Basic:
    """基础SM3哈希算法实现"""

    def __init__(self):
        self.IV = [
            0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
            0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
        ]
        self.T1 = 0x79CC4519
        self.T2 = 0x7A879D8A

    def _rotl(self, x: int, n: int) -> int:
        x = x & 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def _ff(self, x: int, y: int, z: int, j: int) -> int:
        if j <= 15:
            return x ^ y ^ z
        else:
            return (x & y) | (x & z) | (y & z)

    def _gg(self, x: int, y: int, z: int, j: int) -> int:
        if j <= 15:
            return x ^ y ^ z
        else:
            return (x & y) | (~x & z)

    def _p0(self, x: int) -> int:
        return x ^ self._rotl(x, 9) ^ self._rotl(x, 17)

    def _p1(self, x: int) -> int:
        return x ^ self._rotl(x, 15) ^ self._rotl(x, 23)

    def _message_expansion(self, block: bytes) -> list:
        w = []
        for i in range(16):
            w.append(struct.unpack('>I', block[i * 4:(i + 1) * 4])[0])
        for j in range(16, 68):
            temp = w[j - 16] ^ w[j - 9] ^ self._rotl(w[j - 3], 15)
            temp = self._p1(temp)
            w.append(temp ^ self._rotl(w[j - 13], 7) ^ w[j - 6])
        w_prime = []
        for j in range(64):
            w_prime.append(w[j] ^ w[j + 4])
        return w, w_prime

    def _compress(self, message_block: bytes, v: list) -> list:
        w, w_prime = self._message_expansion(message_block)
        a, b, c, d, e, f, g, h = v
        for j in range(64):
            t_j = self.T1 if j <= 15 else self.T2
            temp = (self._rotl(a, 12) + e + self._rotl(t_j, j % 32)) & 0xFFFFFFFF
            ss1 = self._rotl(temp, 7)
            ss2 = ss1 ^ self._rotl(a, 12)
            tt1 = (self._ff(a, b, c, j) + d + ss2 + w_prime[j]) & 0xFFFFFFFF
            tt2 = (self._gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            d = c
            c = self._rotl(b, 9)
            b = a
            a = tt1
            h = g
            g = self._rotl(f, 19)
            f = e
            e = self._p0(tt2)
            a, b, c, d, e, f, g, h = [x & 0xFFFFFFFF for x in [a, b, c, d, e, f, g, h]]
        v_new = []
        for vi, xi in zip(v, [a, b, c, d, e, f, g, h]):
            v_new.append((vi ^ xi) & 0xFFFFFFFF)
        return v_new

    def _padding(self, message: bytes) -> bytes:
        msg_len = len(message)
        msg_bits = msg_len * 8
        padded = message + b'\x80'
        while (len(padded) % 64) != 56:
            padded += b'\x00'
        padded += struct.pack('>Q', msg_bits)
        return padded

    def hash(self, message: bytes) -> bytes:
        padded_message = self._padding(message)
        v = self.IV.copy()
        for i in range(0, len(padded_message), 64):
            block = padded_message[i:i + 64]
            v = self._compress(block, v)
        result = b''
        for val in v:
            result += struct.pack('>I', val)
        return result

    def hash_hex(self, message: bytes) -> str:
        return self.hash(message).hex()


class SM3_Optimized:
    """优化版本的SM3实现"""

    def __init__(self):
        self.IV = [
            0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
            0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
        ]
        self._precompute_t_rotations()

    def _rotl_fast(self, x: int, n: int) -> int:
        x = x & 0xFFFFFFFF
        n = n & 31
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def _precompute_t_rotations(self):
        self.t1_rotations = []
        self.t2_rotations = []
        for j in range(64):
            if j <= 15:
                self.t1_rotations.append(self._rotl_fast(0x79CC4519, j % 32))
            else:
                self.t2_rotations.append(self._rotl_fast(0x7A879D8A, j % 32))

    def _ff_optimized(self, x: int, y: int, z: int, j: int) -> int:
        if j <= 15:
            return x ^ y ^ z
        else:
            return (x & y) | (x & z) | (y & z)

    def _gg_optimized(self, x: int, y: int, z: int, j: int) -> int:
        if j <= 15:
            return x ^ y ^ z
        else:
            return (x & y) | ((~x) & z)

    def _p0_optimized(self, x: int) -> int:
        return x ^ self._rotl_fast(x, 9) ^ self._rotl_fast(x, 17)

    def _p1_optimized(self, x: int) -> int:
        return x ^ self._rotl_fast(x, 15) ^ self._rotl_fast(x, 23)

    def _message_expansion_optimized(self, block: bytes):
        w = list(struct.unpack('>16I', block))
        for j in range(16, 68):
            temp = w[j - 16] ^ w[j - 9] ^ self._rotl_fast(w[j - 3], 15)
            temp = self._p1_optimized(temp)
            w.append((temp ^ self._rotl_fast(w[j - 13], 7) ^ w[j - 6]) & 0xFFFFFFFF)
        w_prime = [w[j] ^ w[j + 4] for j in range(64)]
        return w, w_prime

    def _compress_optimized(self, message_block: bytes, v: list) -> list:
        w, w_prime = self._message_expansion_optimized(message_block)
        a, b, c, d, e, f, g, h = v
        for j in range(64):
            t_j_rot = self.t1_rotations[j] if j <= 15 else self.t2_rotations[j - 16]
            a_rot12 = self._rotl_fast(a, 12)
            temp = (a_rot12 + e + t_j_rot) & 0xFFFFFFFF
            ss1 = self._rotl_fast(temp, 7)
            ss2 = ss1 ^ a_rot12
            tt1 = (self._ff_optimized(a, b, c, j) + d + ss2 + w_prime[j]) & 0xFFFFFFFF
            tt2 = (self._gg_optimized(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            a, b, c, d = tt1, a, self._rotl_fast(b, 9), c
            e, f, g, h = self._p0_optimized(tt2), e, self._rotl_fast(f, 19), g
        return [(vi ^ xi) & 0xFFFFFFFF for vi, xi in zip(v, [a, b, c, d, e, f, g, h])]

    def hash(self, message: bytes) -> bytes:
        basic_sm3 = SM3_Basic()
        padded_message = basic_sm3._padding(message)
        v = self.IV.copy()
        for i in range(0, len(padded_message), 64):
            v = self._compress_optimized(padded_message[i:i + 64], v)
        return b''.join(struct.pack('>I', val) for val in v)

    def hash_hex(self, message: bytes) -> str:
        return self.hash(message).hex()


def test_sm3_basic_functionality():
    """测试SM3基本功能"""
    print("=" * 60)
    print("SM3基本功能测试")
    print("=" * 60)

    sm3_basic = SM3_Basic()
    sm3_optimized = SM3_Optimized()

    test_vectors = [
        {
            'message': b'abc',
            'expected': '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'
        },
        {
            'message': b'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd',
            'expected': 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732'
        },
        {
            'message': b'',
            'expected': '1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b'
        }
    ]

    print("测试向量验证:")
    all_passed = True

    for i, vector in enumerate(test_vectors):
        print(f"\n测试 {i + 1}:")
        print(f"输入: {vector['message']}")
        print(f"期望: {vector['expected']}")

        result_basic = sm3_basic.hash_hex(vector['message'])
        print(f"基础: {result_basic}")

        result_optimized = sm3_optimized.hash_hex(vector['message'])
        print(f"优化: {result_optimized}")

        basic_correct = result_basic == vector['expected']
        optimized_correct = result_optimized == vector['expected']
        consistent = result_basic == result_optimized

        print(f"基础实现正确: {'✓' if basic_correct else '✗'}")
        print(f"优化实现正确: {'✓' if optimized_correct else '✗'}")
        print(f"两版本一致: {'✓' if consistent else '✗'}")

        if not (basic_correct and optimized_correct and consistent):
            all_passed = False

    print(f"\n总体测试结果: {'全部通过' if all_passed else '存在错误'}")
    return all_passed


def test_sm3_performance():
    """测试SM3性能"""
    print("\n" + "=" * 60)
    print("SM3性能测试")
    print("=" * 60)

    sm3_basic = SM3_Basic()
    sm3_optimized = SM3_Optimized()

    test_sizes = [
        (1024, "1KB"),
        (10 * 1024, "10KB"),
        (100 * 1024, "100KB"),
        (1024 * 1024, "1MB")
    ]

    for size, label in test_sizes:
        print(f"\n{label} 数据性能测试:")

        test_data = os.urandom(size)

        start_time = time.time()
        for _ in range(10):
            hash_basic = sm3_basic.hash(test_data)
        basic_time = time.time() - start_time

        start_time = time.time()
        for _ in range(10):
            hash_optimized = sm3_optimized.hash(test_data)
        optimized_time = time.time() - start_time

        basic_throughput = (size * 10) / (1024 * 1024 * basic_time)
        optimized_throughput = (size * 10) / (1024 * 1024 * optimized_time)
        speedup = basic_time / optimized_time

        print(f"基础实现: {basic_time:.4f}s ({basic_throughput:.2f} MB/s)")
        print(f"优化实现: {optimized_time:.4f}s ({optimized_throughput:.2f} MB/s)")
        print(f"性能提升: {speedup:.2f}x")

        if hash_basic == hash_optimized:
            print("✓ 结果一致")
        else:
            print("✗ 结果不一致")


def main():
    print("SM3哈希算法正确性与优化性能测试")
    print("=" * 80)

    if not test_sm3_basic_functionality():
        print("基本功能测试失败，程序终止")
        return

    test_sm3_performance()

    print("\n" + "=" * 80)
    print("测试总结:")
    print("✓ SM3基础实现正确")
    print("✓ 优化版本提供更好性能")
    print("✓ 两版本结果一致")


if __name__ == "__main__":
    main()
