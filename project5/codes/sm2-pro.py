import secrets
import hashlib

# ========== 椭圆曲线参数 ==========
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
G = (Gx, Gy)

# ========== 基础实现 ==========
def inverse_mod(a, m):
    if a == 0:
        raise ZeroDivisionError('division by zero')
    lm, hm = 1, 0
    low, high = a % m, m
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % m

def point_add(P, Q):
    if P == (None, None):
        return Q
    if Q == (None, None):
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return (None, None)
    if P == Q:
        return point_double(P)
    l = ((y2 - y1) * inverse_mod(x2 - x1, p)) % p
    x3 = (l * l - x1 - x2) % p
    y3 = (l * (x1 - x3) - y1) % p
    return (x3, y3)

def point_double(P):
    x1, y1 = P
    if y1 == 0:
        return (None, None)
    l = ((3 * x1 * x1 + a) * inverse_mod(2 * y1, p)) % p
    x3 = (l * l - 2 * x1) % p
    y3 = (l * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(k, P):
    R = (None, None)
    while k:
        if k & 1:
            R = point_add(R, P)
        P = point_double(P)
        k >>= 1
    return R

def gen_keypair_basic():
    d = secrets.randbelow(n-1) + 1
    P = scalar_mult(d, G)
    return d, P

def hash_msg(msg: bytes) -> int:
    # 实际应使用SM3，这里用sha256代替
    return int.from_bytes(hashlib.sha256(msg).digest(), 'big')

def sign_basic(msg: bytes, d):
    e = hash_msg(msg)
    while True:
        k = secrets.randbelow(n-1) + 1
        x1, y1 = scalar_mult(k, G)
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue
        s = (inverse_mod(1 + d, n) * (k - r * d)) % n
        if s == 0:
            continue
        return (r, s)

def verify_basic(msg: bytes, sig, P):
    r, s = sig
    e = hash_msg(msg)
    if not (1 <= r <= n-1 and 1 <= s <= n-1):
        return False
    t = (r + s) % n
    if t == 0:
        return False
    x1, y1 = point_add(scalar_mult(s, G), scalar_mult(t, P))
    R = (e + x1) % n
    return R == r

# ========== 优化实现（gmssl库） ==========
def gen_keypair_gmssl():
    from gmssl import sm2, func
    private_key = func.random_hex(32)
    sm2_crypt = sm2.CryptSM2(public_key='', private_key=private_key)
    public_key = sm2_crypt._kg(int(private_key, 16), sm2_crypt.ecc_table['g'])
    return private_key, public_key

def sign_gmssl(msg: bytes, private_key, public_key):
    from gmssl import sm2, func
    sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)
    sign = sm2_crypt.sign(msg, func.random_hex(sm2_crypt.para_len))
    return sign

def verify_gmssl(msg: bytes, sign, public_key):
    from gmssl import sm2
    sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key='')
    return sm2_crypt.verify(sign, msg)

# ========== 统一接口 ==========
def sm2_demo(use_optimized=False):
    msg = b"hello, sm2!"
    print("消息:", msg)
    if not use_optimized:
        print("=== 基础实现 ===")
        d, P = gen_keypair_basic()
        sig = sign_basic(msg, d)
        print("签名:", sig)
        print("验签:", verify_basic(msg, sig, P))
    else:
        print("=== 优化实现（gmssl） ===")
        private_key, public_key = gen_keypair_gmssl()
        sign = sign_gmssl(msg, private_key, public_key)
        print("签名:", sign)
        print("验签:", verify_gmssl(msg, sign, public_key))

# ========== 运行测试 ==========
if __name__ == "__main__":
    print("【基础实现】")
    sm2_demo(use_optimized=False)
    print("\n【优化实现】")
    sm2_demo(use_optimized=True)