import random
import hashlib
import math
from dataclasses import dataclass
from typing import List, Tuple

# 参数
RFC3526_MODP_2048_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
RFC3526_MODP_2048_G = 2
RFC3526_MODP_2048_Q = (RFC3526_MODP_2048_P - 1) // 2  #安全素数 q

def sha256_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), "big")

def hash_to_group(u: str) -> int:
    x = sha256_int(u.encode("utf-8")) % RFC3526_MODP_2048_Q
    if x == 0:
        x = 1
    return pow(RFC3526_MODP_2048_G, x, RFC3526_MODP_2048_P)

# 简单 Paillier 实现
def _is_probable_prime(n: int, k: int = 16) -> bool:
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True

def _rand_prime(bits: int) -> int:
    while True:
        cand = random.getrandbits(bits) | 1 | (1 << (bits - 1))
        if _is_probable_prime(cand):
            return cand

@dataclass
class PaillierPublicKey:
    n: int
    n2: int
    g: int

@dataclass
class PaillierSecretKey:
    lam: int
    mu: int
    n: int
    n2: int
    g: int

# 生成 Paillier 密钥对
def paillier_keygen(bits: int = 512) -> Tuple[PaillierPublicKey, PaillierSecretKey]:
    p = _rand_prime(bits // 2)
    q = _rand_prime(bits // 2)
    while q == p:
        q = _rand_prime(bits // 2)
    n = p * q
    n2 = n * n
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    g = n + 1 
    def L(u): return (u - 1) // n
    mu = pow(L(pow(g, lam, n2)), -1, n)
    pk = PaillierPublicKey(n=n, n2=n2, g=g)
    sk = PaillierSecretKey(lam=lam, mu=mu, n=n, n2=n2, g=g)
    return pk, sk

def paillier_enc(pk: PaillierPublicKey, m: int) -> int:
    m = m % pk.n
    while True:
        r = random.randrange(1, pk.n)
        if math.gcd(r, pk.n) == 1:
            break
    c = (pow(pk.g, m, pk.n2) * pow(r, pk.n, pk.n2)) % pk.n2
    return c

def paillier_dec(sk: PaillierSecretKey, c: int) -> int:
    def L(u, n): return (u - 1) // n
    u = pow(c, sk.lam, sk.n2)
    m = (L(u, sk.n) * sk.mu) % sk.n
    return m

def paillier_add(pk: PaillierPublicKey, c1: int, c2: int) -> int:
    return (c1 * c2) % pk.n2

def paillier_rerandomize(pk: PaillierPublicKey, c: int) -> int:
    while True:
        r = random.randrange(1, pk.n)
        if math.gcd(r, pk.n) == 1:
            break
    return (c * pow(r, pk.n, pk.n2)) % pk.n2

@dataclass
class P1Input:
    V: List[str] 

@dataclass
class P2Input:
    W: List[Tuple[str, int]]  

def ddh_pis_protocol(P1: P1Input, P2: P2Input, paillier_bits: int = 512, verbose: bool = True):

    p = RFC3526_MODP_2048_P
    q = RFC3526_MODP_2048_Q
    g = RFC3526_MODP_2048_G

    k1 = random.randrange(1, q)
    k2 = random.randrange(1, q)
    if verbose:
        print("初始化（Setup）")
        print("P1 随机选取私钥 k1，P2 随机选取私钥 k2（保密）")
        print("P2 生成 Paillier 密钥对并把公钥发送给 P1")

    pk, sk = paillier_keygen(bits=paillier_bits)
    if verbose:
        print(f"已生成 Paillier 密钥（公钥模 n 的位长约 {pk.n.bit_length()} 位）")
        print()

    R1 = [pow(hash_to_group(vi), k1, p) for vi in P1.V]
    random.shuffle(R1)  # 打乱顺序以防位置关联
    if verbose:
        print("第 1 轮")
        print(f"P1 对 V 中 {len(P1.V)} 个元素计算 H(v)^{k1} 并打乱后发送给 P2。")
        print()

    Z = [pow(x, k2, p) for x in R1]
    random.shuffle(Z)
    pairs = []
    for (wj, tj) in P2.W:
        h_w_k2 = pow(hash_to_group(wj), k2, p)
        enc_tj = paillier_enc(pk, tj)
        pairs.append((h_w_k2, enc_tj))
    random.shuffle(pairs)
    if verbose:
        print("第 2 轮")
        print(f"P2 对收到的 R1 中每项再做 ^k2，得到 Z 并发送给 P1。")
        print(f"P2 还发送其自身 W 转换后的配对 (H(w)^{k2}, Enc(t)) 共 {len(pairs)} 项，顺序也已打乱。")
        print()

    pairs_k1 = [(pow(hk2, k1, p), ct) for (hk2, ct) in pairs]  
    Zset = set(Z)
    J_indices = [i for i, (h12, ct) in enumerate(pairs_k1) if h12 in Zset]
    if verbose:
        print("第 3 轮")
        print("P1 将接收到的 pairs 中的第一分量再做 ^k1，变为 H(w)^{k1 k2}，并与 Z 比较匹配。")
        print(f"P1 识别出交集中的元素数量（|J|） = {len(J_indices)}")
        print()

    if not J_indices:
        C_sum = paillier_enc(pk, 0)  
    else:
        C_sum = pairs_k1[J_indices[0]][1]
        for idx in J_indices[1:]:
            C_sum = paillier_add(pk, C_sum, pairs_k1[idx][1])

    C_rand = paillier_rerandomize(pk, C_sum)
    if verbose:
        print("P1 对同态求和结果进行重随机化后发送给 P2。")
        print()

    # P2 用私钥解密得到交集求和结果
    sum_value = paillier_dec(sk, C_rand)
    if verbose:
        print("输出")
        print(f"P2 解密得到交集元素对应 t 值之和 = {sum_value}")
        print()

    expected = 0
    intersected = []
    P1set = set(P1.V)
    for (w, t) in P2.W:
        if w in P1set:
            expected += t
            intersected.append(w)
    if verbose:
        print(f"  交集元素（明文） = {intersected}")
        print(f"  明文求和（期望） = {expected}")
        if sum_value == expected:
            print(" 解密结果与期望一致。")
        else:
            print(" 解密结果与期望不一致。")
    return {
        "decrypted_sum": sum_value,
        "expected_sum": expected,
        "intersection_items": intersected,
        "J_size": len(J_indices),
        "paillier_n_bits": pk.n.bit_length()
    }

def main_demo():
    random.seed(42)
    P1 = P1Input(V=["alice", "bob", "carol", "dave"])
    P2 = P2Input(W=[("bob", 5), ("erin", 7), ("carol", 11), ("frank", 13)])

    print("输入：")
    print("  P1 的集合 V =", P1.V)
    print("  P2 的集合 W (带权重) =", P2.W)
    print()

    # 运行协议
    result = ddh_pis_protocol(P1, P2, paillier_bits=512, verbose=True)

    print()
    print("最终摘要：")
    print("  解密得到的交集求和 =", result["decrypted_sum"])
    print("  明文期望的交集求和 =", result["expected_sum"])
    print("  明文交集元素列表 =", result["intersection_items"])
    print("  P1识别出的交集大小 |J| =", result["J_size"])
    print("  Paillier模n的位长度 =", result["paillier_n_bits"])

if __name__ == "__main__":
    main_demo()
