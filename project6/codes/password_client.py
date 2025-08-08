import random
from password_checkup_protocol import double_encrypt

def client_protocol(user_hashes_hex, leaked_hashes, k1, k2, enc_tjs, paillier_pub):
    # 1. 用户端哈希
    user_hashes = [bytes.fromhex(h) for h in user_hashes_hex]
    # 2. 双方都计算double_encrypted
    user_double = [double_encrypt(h, k1, k2) for h in user_hashes]
    leaked_double = [double_encrypt(h, k1, k2) for h in leaked_hashes]
    # 3. 比对交集
    intersection_indices = []
    for i, u in enumerate(user_double):
        for j, l in enumerate(leaked_double):
            if u == l:
                intersection_indices.append(j)
    print(f"交集索引: {intersection_indices}")
    # 4. 对交集Paillier密文求和
    if intersection_indices:
        enc_sum = enc_tjs[intersection_indices[0]]
        for idx in intersection_indices[1:]:
            enc_sum += enc_tjs[idx]
    else:
        enc_sum = paillier_pub.encrypt(0)
    return enc_sum