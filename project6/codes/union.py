import hashlib
import random
from tinyec import registry
from phe import paillier

curve = registry.get_curve('secp256r1')
G = curve.g

def hash_password(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def hash_to_point(data: bytes):
    # 直接用哈希值做标量，乘基点G
    scalar = int.from_bytes(data, 'big') % curve.field.n
    if scalar == 0:
        scalar = 1
    return scalar * G

def point_to_bytes(point):
    return point.x.to_bytes(32, 'big') + point.y.to_bytes(32, 'big')

def password_checkup_protocol(user_passwords, leaked_passwords):
    print("=== Google Password Checkup 协议（严格版） ===")
    paillier_pub, paillier_priv = paillier.generate_paillier_keypair()
    k1 = random.randint(1, curve.field.n - 1)
    k2 = random.randint(1, curve.field.n - 1)

    user_hashes = [hash_password(p) for p in user_passwords]
    user_points = [hash_to_point(h) for h in user_hashes]
    user_points_k1 = [k1 * pt for pt in user_points]

    leaked_hashes = [hash_password(p) for p in leaked_passwords]
    leaked_points = [hash_to_point(h) for h in leaked_hashes]
    leaked_points_k2 = [k2 * pt for pt in leaked_points]
    tjs = [1 for _ in leaked_points]
    enc_tjs = [paillier_pub.encrypt(t) for t in tjs]

    user_points_k1k2 = [k2 * pt for pt in user_points_k1]
    user_points_k1k2_bytes = [point_to_bytes(pt) for pt in user_points_k1k2]

    leaked_points_k2k1 = [k1 * pt for pt in leaked_points_k2]
    leaked_points_k2k1_bytes = [point_to_bytes(pt) for pt in leaked_points_k2k1]

    intersection_indices = []
    for i, up in enumerate(user_points_k1k2_bytes):
        for j, lp in enumerate(leaked_points_k2k1_bytes):
            if up == lp:
                intersection_indices.append(j)
    print(f"交集索引: {intersection_indices}")

    if intersection_indices:
        enc_sum = enc_tjs[intersection_indices[0]]
        for idx in intersection_indices[1:]:
            enc_sum += enc_tjs[idx]
    else:
        enc_sum = paillier_pub.encrypt(0)

    S = paillier_priv.decrypt(enc_sum)
    print(f"交集和 S = {S}，即有 {S} 个密码在泄露集合中。")
    if S > 0:
        print("警告：检测到密码泄露！")
    else:
        print("未检测到密码泄露。")

if __name__ == "__main__":
    user_passwords = ['qwerty', 'mypassword', 'letmein']
    leaked_passwords = ['123456', 'password', 'letmein', 'qwerty']
    password_checkup_protocol(user_passwords, leaked_passwords)