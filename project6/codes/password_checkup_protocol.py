import hashlib
from tinyec import registry

curve = registry.get_curve('secp256r1')
G = curve.g

def hash_password(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def hash_to_point_bytes(hash_hex: str):
    # 用哈希值做标量，乘基点G，保证一定在曲线上
    scalar = int(hash_hex, 16) % curve.field.n
    if scalar == 0:
        scalar = 1
    pt = scalar * G
    return pt

def point_to_bytes(point):
    return point.x.to_bytes(32, 'big') + point.y.to_bytes(32, 'big')