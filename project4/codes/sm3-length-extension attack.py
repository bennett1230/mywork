import struct

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

    def _ff(self, x, y, z, j):
        return x ^ y ^ z if j <= 15 else (x & y) | (x & z) | (y & z)

    def _gg(self, x, y, z, j):
        return x ^ y ^ z if j <= 15 else (x & y) | (~x & z)

    def _p0(self, x):
        return x ^ self._rotl(x, 9) ^ self._rotl(x, 17)

    def _p1(self, x):
        return x ^ self._rotl(x, 15) ^ self._rotl(x, 23)

    def _message_expansion(self, block):
        w = [struct.unpack('>I', block[i * 4:(i + 1) * 4])[0] for i in range(16)]
        for j in range(16, 68):
            temp = w[j - 16] ^ w[j - 9] ^ self._rotl(w[j - 3], 15)
            temp = self._p1(temp)
            w.append(temp ^ self._rotl(w[j - 13], 7) ^ w[j - 6])
        w_prime = [w[j] ^ w[j + 4] for j in range(64)]
        return w, w_prime

    def _compress(self, message_block, v):
        w, w_prime = self._message_expansion(message_block)
        a, b, c, d, e, f, g, h = v
        for j in range(64):
            t_j = self.T1 if j <= 15 else self.T2
            temp = (self._rotl(a, 12) + e + self._rotl(t_j, j % 32)) & 0xFFFFFFFF
            ss1 = self._rotl(temp, 7)
            ss2 = ss1 ^ self._rotl(a, 12)
            tt1 = (self._ff(a, b, c, j) + d + ss2 + w_prime[j]) & 0xFFFFFFFF
            tt2 = (self._gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            d, c, b, a = c, self._rotl(b, 9), a, tt1
            h, g, f, e = g, self._rotl(f, 19), e, self._p0(tt2)
            a, b, c, d, e, f, g, h = [x & 0xFFFFFFFF for x in [a, b, c, d, e, f, g, h]]
        return [(vi ^ xi) & 0xFFFFFFFF for vi, xi in zip(v, [a, b, c, d, e, f, g, h])]

    def _padding(self, message):
        msg_len = len(message)
        msg_bits = msg_len * 8
        padded = message + b'\x80'
        while (len(padded) % 64) != 56:
            padded += b'\x00'
        padded += struct.pack('>Q', msg_bits)
        return padded

    def hash(self, message):
        padded_message = self._padding(message)
        v = self.IV.copy()
        for i in range(0, len(padded_message), 64):
            block = padded_message[i:i + 64]
            v = self._compress(block, v)
        result = b''.join(struct.pack('>I', val) for val in v)
        return result

    def hash_hex(self, message):
        return self.hash(message).hex()


class SM3_LengthExtensionAttack:
    """SM3长度扩展攻击演示"""

    def __init__(self):
        self.sm3 = SM3_Basic()

    def _generate_padding(self, original_length: int) -> bytes:
        msg_bits = original_length * 8
        padding = b'\x80'
        while ((original_length + len(padding)) % 64) != 56:
            padding += b'\x00'
        padding += struct.pack('>Q', msg_bits)
        return padding

    def forge_hash(self, original_hash: bytes, original_length: int, additional_data: bytes):
        # 1. 计算原始消息的填充
        padding = self._generate_padding(original_length)
        # 2. 恢复内部状态
        state = list(struct.unpack('>8I', original_hash))
        # 3. 计算扩展消息的总长度
        extended_msg_length = original_length + len(padding) + len(additional_data)
        # 4. 为扩展消息生成填充
        extended_padding = self._generate_padding(extended_msg_length)
        # 5. 构造要处理的数据
        to_process = additional_data + extended_padding
        # 6. 从原始状态开始处理新数据
        v = state
        for i in range(0, len(to_process), 64):
            block = to_process[i:i + 64]
            v = self.sm3._compress(block, v)
        # 7. 返回完整后缀和计算出的哈希
        complete_suffix = padding + additional_data
        result_hash = b''.join(struct.pack('>I', val) for val in v)
        return complete_suffix, result_hash

def demonstrate_length_extension_attack():
    print("=" * 60)
    print("SM3 长度扩展攻击演示")
    print("=" * 60)

    # 场景设置
    secret_key = b"super_secret_key_12345"  # 服务器密钥（攻击者不知道）
    known_message = b"user=alice&role=user"  # 攻击者已知的消息
    malicious_data = b"&role=admin"         # 攻击者想要添加的数据

    # 1. 服务器端计算原始MAC
    sm3 = SM3_Basic()
    original_mac = sm3.hash(secret_key + known_message)
    print(f"原始消息: {known_message}")
    print(f"原始MAC: {original_mac.hex()}")

    # 2. 攻击者执行长度扩展攻击
    attack = SM3_LengthExtensionAttack()
    orig_len = len(secret_key + known_message)
    suffix, forged_mac = attack.forge_hash(original_mac, orig_len, malicious_data)

    # 3. 伪造消息
    forged_message = secret_key + known_message + suffix
    print(f"\n伪造消息: {forged_message}")
    print(f"伪造MAC: {forged_mac.hex()}")

    # 4. 服务器端验证
    real_mac = sm3.hash(forged_message)
    print(f"\n服务器端实际计算MAC: {real_mac.hex()}")
    print(f"攻击成功: {'是' if real_mac == forged_mac else '否'}")

if __name__ == "__main__":
    demonstrate_length_extension_attack()
