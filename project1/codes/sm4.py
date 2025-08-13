import time

class SM4:

    # S盒
    S_BOX = [
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

    # 系统参数FK
    FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

    # 固定参数CK
    CK = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ]

    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("SM4 密钥必须是 16 bytes (128 bits) 长")
        self.rk = self._expand_key(key)

    @staticmethod
    def _rotl(x, n):
        """循环左移"""
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _tau(a):
        """非线性变换τ(.)"""
        a0 = (a >> 24) & 0xFF
        a1 = (a >> 16) & 0xFF
        a2 = (a >> 8) & 0xFF
        a3 = a & 0xFF

        b0 = SM4.S_BOX[a0]
        b1 = SM4.S_BOX[a1]
        b2 = SM4.S_BOX[a2]
        b3 = SM4.S_BOX[a3]

        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

    def _l(self, b):
        """线性变换L"""
        return b ^ self._rotl(b, 2) ^ self._rotl(b, 10) ^ self._rotl(b, 18) ^ self._rotl(b, 24)

    def _l_prime(self, b):
        """线性变换L'"""
        return b ^ self._rotl(b, 13) ^ self._rotl(b, 23)

    def _t(self, x):
        """合成变换T"""
        return self._l(self._tau(x))

    def _t_prime(self, x):
        """合成变换T'"""
        return self._l_prime(self._tau(x))

    def _expand_key(self, key):
        """密钥扩展算法"""
        # 将密钥转换为4个字
        mk = [0] * 4
        for i in range(4):
            mk[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3]

        # 生成中间密钥K
        k = [0] * 36
        for i in range(4):
            k[i] = mk[i] ^ SM4.FK[i]

        # 生成轮密钥rk
        rk = [0] * 32
        for i in range(32):
            k[i + 4] = k[i] ^ self._t_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4.CK[i])
            rk[i] = k[i + 4]

        return rk

    def _f(self, x0, x1, x2, x3, rk):
        """轮函数F"""
        return x0 ^ self._t(x1 ^ x2 ^ x3 ^ rk)

    def _crypt(self, input_data, decrypt=False):
        """加/解密函数"""
        if len(input_data) != 16:
            raise ValueError("SM4 block size must be 16 bytes (128 bits)")

        start_time = time.perf_counter()  # 开始计时

        # 将输入数据转换为4个字
        x = [0] * 36
        for i in range(4):
            x[i] = (input_data[4 * i] << 24) | (input_data[4 * i + 1] << 16) | (input_data[4 * i + 2] << 8) | \
                   input_data[4 * i + 3]

        # 32轮迭代
        rk = self.rk
        if decrypt:
            rk = rk[::-1]  # 解密时使用逆序轮密钥

        for i in range(32):
            x[i + 4] = self._f(x[i], x[i + 1], x[i + 2], x[i + 3], rk[i])

        # 反序变换
        output = bytearray(16)
        for i in range(4):
            output[4 * i] = (x[35 - i] >> 24) & 0xFF
            output[4 * i + 1] = (x[35 - i] >> 16) & 0xFF
            output[4 * i + 2] = (x[35 - i] >> 8) & 0xFF
            output[4 * i + 3] = x[35 - i] & 0xFF

        elapsed = (time.perf_counter() - start_time) * 1000  # 毫秒
        self.last_operation_time = elapsed

        return bytes(output)

    def encrypt(self, plaintext):
        """加密"""
        return self._crypt(plaintext, decrypt=False)

    def decrypt(self, ciphertext):
        """解密"""
        return self._crypt(ciphertext, decrypt=True)


def interactive_demo():

    print("SM4加密算法交互演示")
    print("=" * 40)

    while True:
        key_hex = input("请输入16字节(32字符)的16进制密钥(例如:0123456789abcdeffedcba9876543210): ").strip()
        try:
            if len(key_hex) != 32:
                raise ValueError("密钥长度必须为32个16进制字符")
            key = bytes.fromhex(key_hex)
            break
        except ValueError as e:
            print(f"无效输入: {e}")

    sm4 = SM4(key)

    while True:
        print("\n请选择操作:")
        print("1. 加密")
        print("2. 解密")
        print("3. 退出")
        choice = input("您的选择(1/2/3): ").strip()

        if choice == '3':
            print("退出程序。")
            break

        if choice not in ('1', '2'):
            print("无效选择，请重新输入")
            continue

        while True:
            data_hex = input("请输入16字节(32字符)的16进制数据: ").strip()
            try:
                if len(data_hex) != 32:
                    raise ValueError("数据长度必须为32个16进制字符")
                data = bytes.fromhex(data_hex)
                break
            except ValueError as e:
                print(f"无效输入: {e}")

        start_time = time.perf_counter()
        if choice == '1':
            result = sm4.encrypt(data)
            operation = "加密"
        else:
            result = sm4.decrypt(data)
            operation = "解密"
        elapsed = (time.perf_counter() - start_time) * 1000  # 毫秒

        print(f"\n{operation}结果: {result.hex()}")
        print(f"内部方法耗时: {sm4.last_operation_time:.6f} 毫秒")
        print(f"总操作耗时: {elapsed:.6f} 毫秒")

        # 显示详细信息
        print("\n详细信息:")
        print(f"密钥: {key.hex()}")
        print(f"输入: {data.hex()}")
        print(f"输出: {result.hex()}")


if __name__ == "__main__":

    interactive_demo()
