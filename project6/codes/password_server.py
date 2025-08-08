import random
from phe import paillier

def server_prepare(leaked_hashes_hex):
    # 1. 生成Paillier密钥对
    paillier_pub, paillier_priv = paillier.generate_paillier_keypair()
    # 2. 生成服务端私钥k2
    k2 = random.randint(1, 2**128)
    # 3. 读取泄露哈希
    leaked_hashes = [bytes.fromhex(h) for h in leaked_hashes_hex]
    tjs = [1 for _ in leaked_hashes]
    enc_tjs = [paillier_pub.encrypt(t) for t in tjs]
    return paillier_pub, paillier_priv, k2, leaked_hashes, enc_tjs

def server_finalize(paillier_priv, enc_sum):
    S = paillier_priv.decrypt(enc_sum)
    print(f"交集和 S = {S}，即有 {S} 个密码在泄露集合中。")
    if S > 0:
        print("警告：检测到密码泄露！")
    else:
        print("未检测到密码泄露。")