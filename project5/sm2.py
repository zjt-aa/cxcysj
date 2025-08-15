import os
import time
import struct
from typing import Tuple, Optional

# 椭圆曲线参数
p  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

# 辅助函数 
def int_to_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, 'big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def mod_inv(x: int, m: int = p) -> int:
    return pow(x, m - 2, m)

# 椭圆曲线运算 
Point = Optional[Tuple[int, int]]
O: Point = None

def is_on_curve(P: Point) -> bool:
    if P is None: return True
    x, y = P
    return (y * y - (x * x * x + a * x + b)) % p == 0

def point_add(P: Point, Q: Point) -> Point:
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P != Q:
        lam = ((y2 - y1) * mod_inv((x2 - x1) % p, p)) % p
    else:
        lam = ((3 * x1 * x1 + a) * mod_inv((2 * y1) % p, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(k: int, P: Point) -> Point:
    if k % n == 0 or P is None:
        return None
    if k < 0:
        return scalar_mult(-k, (P[0], (-P[1]) % p))
    R = None
    Q = P
    while k:
        if k & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        k >>= 1
    return R

# SM3 哈希
def _rotl(x, n):
    n = n % 32
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def _P0(x: int) -> int:
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)

def _P1(x: int) -> int:
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)

T_j = [0x79cc4519] * 16 + [0x7a879d8a] * 48

def sm3_compress(V: int, B: bytes) -> int:
    W = [bytes_to_int(B[4 * i:4 * i + 4]) for i in range(16)]
    for j in range(16, 68):
        x = W[j - 16] ^ W[j - 9] ^ _rotl(W[j - 3], 15)
        W.append(_P1(x) ^ _rotl(W[j - 13], 7) ^ W[j - 6])
    W1 = [W[j] ^ W[j + 4] for j in range(64)]

    Vs = [(V >> (32 * (7 - i))) & 0xFFFFFFFF for i in range(8)]
    A, B1, C, D, E, F, G, H = Vs
    for j in range(64):
        if j <= 15:
            FF = A ^ B1 ^ C
            GG = E ^ F ^ G
        else:
            FF = (A & B1) | (A & C) | (B1 & C)
            GG = (E & F) | ((~E) & G & 0xFFFFFFFF)
        SS1 = _rotl(((_rotl(A, 12) + E + _rotl(T_j[j], j)) & 0xFFFFFFFF), 7)
        SS2 = SS1 ^ _rotl(A, 12)
        TT1 = (FF + D + SS2 + W1[j]) & 0xFFFFFFFF
        TT2 = (GG + H + SS1 + W[j]) & 0xFFFFFFFF
        D, C, B1, A = C, _rotl(B1, 9), A, TT1
        H, G, F, E = G, _rotl(F, 19), E, _P0(TT2)

    Vv = [(Vs[0] ^ A) & 0xFFFFFFFF, (Vs[1] ^ B1) & 0xFFFFFFFF,
          (Vs[2] ^ C) & 0xFFFFFFFF, (Vs[3] ^ D) & 0xFFFFFFFF,
          (Vs[4] ^ E) & 0xFFFFFFFF, (Vs[5] ^ F) & 0xFFFFFFFF,
          (Vs[6] ^ G) & 0xFFFFFFFF, (Vs[7] ^ H) & 0xFFFFFFFF]
    res = 0
    for x in Vv:
        res = (res << 32) | (x & 0xFFFFFFFF)
    return res

def sm3_hash(msg: bytes) -> bytes:
    IV = bytes.fromhex('7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e')
    msg_len = len(msg)
    bit_len = msg_len * 8
    msg_padded = msg + b'\x80'
    k = (56 - (len(msg_padded) % 64)) % 64
    msg_padded += b'\x00' * k
    msg_padded += struct.pack('>Q', bit_len)
    V = int.from_bytes(IV, 'big')
    for i in range(0, len(msg_padded), 64):
        block = msg_padded[i:i + 64]
        V = sm3_compress(V, block)
    return int_to_bytes(V, 32)

def kdf(z: bytes, klen: int) -> bytes:
    ct = 1
    out = b''
    while len(out) < klen:
        out += sm3_hash(z + struct.pack('>I', ct))
        ct += 1
    return out[:klen]

def generate_keypair() -> Tuple[int, Tuple[int, int]]:
    while True:
        d = bytes_to_int(os.urandom(32)) % n
        if 1 <= d < n:
            break
    P = scalar_mult(d, (Gx, Gy))
    return d, P

def point_to_bytes(P: Point) -> bytes:
    if P is None:
        raise ValueError("无穷远点")
    return b'\x04' + int_to_bytes(P[0], 32) + int_to_bytes(P[1], 32)

def bytes_to_point(b: bytes) -> Point:
    if b[0] != 4:
        raise ValueError("只支持未压缩点")
    x = bytes_to_int(b[1:33])
    y = bytes_to_int(b[33:65])
    P = (x, y)
    if not is_on_curve(P):
        raise ValueError("点不在曲线上")
    return P

def sm2_encrypt(pub: Tuple[int, int], msg: bytes) -> bytes:
    mlen = len(msg)
    while True:
        k = bytes_to_int(os.urandom(32)) % n
        if k == 0:
            continue
        C1 = scalar_mult(k, (Gx, Gy))
        S = scalar_mult(k, pub)
        x2, y2 = int_to_bytes(S[0], 32), int_to_bytes(S[1], 32)
        t = kdf(x2 + y2, mlen)
        if int.from_bytes(t, 'big') == 0:
            continue
        C2 = bytes([m ^ t_i for m, t_i in zip(msg, t)])
        C3 = sm3_hash(x2 + msg + y2)
        return point_to_bytes(C1) + C3 + C2

def sm2_decrypt(priv: int, C: bytes) -> bytes:
    C1 = bytes_to_point(C[:65])
    C3 = C[65:97]
    C2 = C[97:]
    S = scalar_mult(priv, C1)
    x2, y2 = int_to_bytes(S[0], 32), int_to_bytes(S[1], 32)
    t = kdf(x2 + y2, len(C2))
    if int.from_bytes(t, 'big') == 0:
        raise ValueError("KDF 输出全 0")
    M = bytes([c ^ t_i for c, t_i in zip(C2, t)])
    if sm3_hash(x2 + M + y2) != C3:
        raise ValueError("C3 校验失败")
    return M

# 测试
def bench(rounds: int = 20):
    print("生成密钥对…")
    d, P = generate_keypair()
    message = b"abc"
    print("原文:", message)

    # 单次验证
    C = sm2_encrypt(P, message)
    M = sm2_decrypt(d, C)
    print("解密结果:", M)
    print("解密正确:", M == message)

    # 加密
    t0 = time.perf_counter()
    for _ in range(rounds):
        sm2_encrypt(P, message)
    t1 = time.perf_counter()
    print(f"平均加密时间: {(t1 - t0) / rounds * 1000:.3f} ms")

    # 解密
    C = sm2_encrypt(P, message)
    t0 = time.perf_counter()
    for _ in range(rounds):
        sm2_decrypt(d, C)
    t1 = time.perf_counter()
    print(f"平均解密时间: {(t1 - t0) / rounds * 1000:.3f} ms")

if __name__ == "__main__":
    bench(10)
