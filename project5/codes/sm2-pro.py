import secrets
import hashlib
import time

# SM2参数
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
G = (Gx, Gy)

# ========== 基础实现（仿射坐标） ==========

def inverse_mod_basic(a, m):
    if a == 0:
        raise ZeroDivisionError('division by zero')
    lm, hm = 1, 0
    low, high = a % m, m
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % m

def point_add_basic(P, Q):
    if P == (None, None):
        return Q
    if Q == (None, None):
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return (None, None)
    if P == Q:
        return point_double_basic(P)
    l = ((y2 - y1) * inverse_mod_basic(x2 - x1, p)) % p
    x3 = (l * l - x1 - x2) % p
    y3 = (l * (x1 - x3) - y1) % p
    return (x3, y3)

def point_double_basic(P):
    x1, y1 = P
    if y1 == 0:
        return (None, None)
    l = ((3 * x1 * x1 + a) * inverse_mod_basic(2 * y1, p)) % p
    x3 = (l * l - 2 * x1) % p
    y3 = (l * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult_basic(k, P):
    R = (None, None)
    while k:
        if k & 1:
            R = point_add_basic(R, P)
        P = point_double_basic(P)
        k >>= 1
    return R

def gen_keypair_basic():
    d = secrets.randbelow(n-1) + 1
    P = scalar_mult_basic(d, G)
    return d, P

def hash_msg(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), 'big')

def sign_basic(msg: bytes, d):
    e = hash_msg(msg)
    while True:
        k = secrets.randbelow(n-1) + 1
        x1, y1 = scalar_mult_basic(k, G)
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue
        s = (inverse_mod_basic(1 + d, n) * (k - r * d)) % n
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
    x1, y1 = point_add_basic(scalar_mult_basic(s, G), scalar_mult_basic(t, P))
    R = (e + x1) % n
    return R == r

# ========== 手动优化实现（Jacobian坐标+内置pow逆元） ==========

def inverse_mod(a, m):
    return pow(a, -1, m)

def jacobian_double(X1, Y1, Z1):
    if not Y1 or not Z1:
        return (0, 0, 0)
    S = (4 * X1 * Y1 * Y1) % p
    M = (3 * X1 * X1 + a * pow(Z1, 4, p)) % p
    X3 = (M * M - 2 * S) % p
    Y3 = (M * (S - X3) - 8 * Y1 * Y1 * Y1 * Y1) % p
    Z3 = (2 * Y1 * Z1) % p
    return (X3, Y3, Z3)

def jacobian_add(X1, Y1, Z1, X2, Y2, Z2):
    if not Y1 or not Z1:
        return (X2, Y2, Z2)
    if not Y2 or not Z2:
        return (X1, Y1, Z1)
    U1 = (X1 * pow(Z2, 2, p)) % p
    U2 = (X2 * pow(Z1, 2, p)) % p
    S1 = (Y1 * pow(Z2, 3, p)) % p
    S2 = (Y2 * pow(Z1, 3, p)) % p
    if U1 == U2:
        if S1 != S2:
            return (0, 0, 1)
        else:
            return jacobian_double(X1, Y1, Z1)
    H = (U2 - U1) % p
    R = (S2 - S1) % p
    H2 = (H * H) % p
    H3 = (H * H2) % p
    U1H2 = (U1 * H2) % p
    X3 = (R * R - H3 - 2 * U1H2) % p
    Y3 = (R * (U1H2 - X3) - S1 * H3) % p
    Z3 = (H * Z1 * Z2) % p
    return (X3, Y3, Z3)

def jacobian_to_affine(X, Y, Z):
    if Z == 0:
        return (None, None)
    Z_inv = inverse_mod(Z, p)
    Z_inv2 = (Z_inv * Z_inv) % p
    x = (X * Z_inv2) % p
    y = (Y * Z_inv2 * Z_inv) % p
    return (x, y)

def scalar_mult_jacobian(k, P):
    X, Y = P
    R = (0, 0, 1)
    Q = (X, Y, 1)
    for i in bin(k)[2:]:
        R = jacobian_double(*R)
        if i == '1':
            R = jacobian_add(*R, *Q)
    return jacobian_to_affine(*R)

def gen_keypair_optimized():
    d = secrets.randbelow(n-1) + 1
    P = scalar_mult_jacobian(d, G)
    return d, P

def sign_optimized(msg: bytes, d):
    e = hash_msg(msg)
    while True:
        k = secrets.randbelow(n-1) + 1
        x1, y1 = scalar_mult_jacobian(k, G)
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue
        s = (inverse_mod(1 + d, n) * (k - r * d)) % n
        if s == 0:
            continue
        return (r, s)

def verify_optimized(msg: bytes, sig, P):
    r, s = sig
    e = hash_msg(msg)
    if not (1 <= r <= n-1 and 1 <= s <= n-1):
        return False
    t = (r + s) % n
    if t == 0:
        return False
    x1, y1 = point_add_basic(scalar_mult_jacobian(s, G), scalar_mult_jacobian(t, P))
    R = (e + x1) % n
    return R == r

# ========== 对比测试 ==========

def sm2_demo_compare(repeat=1):
    msg = b"hello, sm2!"

    print("【基础实现（仿射坐标）】")
    d1, P1 = gen_keypair_basic()
    t1 = time.time()
    for _ in range(repeat):
        sig1 = sign_basic(msg, d1)
    t2 = time.time()
    for _ in range(repeat):
        verify_result1 = verify_basic(msg, sig1, P1)
    t3 = time.time()
    print("签名平均耗时: %.6f s" % ((t2-t1)/repeat))
    print("验签平均耗时: %.6f s" % ((t3-t2)/repeat))
    print("签名结果:", sig1)
    print("验签结果:", verify_result1)

    print("\n【手动优化实现（Jacobian坐标+内置pow逆元）】")
    d2, P2 = gen_keypair_optimized()
    t4 = time.time()
    for _ in range(repeat):
        sig2 = sign_optimized(msg, d2)
    t5 = time.time()
    for _ in range(repeat):
        verify_result2 = verify_optimized(msg, sig2, P2)
    t6 = time.time()
    print("签名平均耗时: %.6f s" % ((t5-t4)/repeat))
    print("验签平均耗时: %.6f s" % ((t6-t5)/repeat))
    print("签名结果:", sig2)
    print("验签结果:", verify_result2)

if __name__ == "__main__":
    repeat = 3  
    sm2_demo_compare(repeat=repeat)
