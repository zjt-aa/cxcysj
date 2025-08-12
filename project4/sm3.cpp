#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <chrono>  

using namespace std;
using namespace std::chrono;

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

u32 Tj(int j) {
    return (j < 16) ? 0x79CC4519 : 0x7A879D8A;
}

u32 left_rotate(u32 x, int n) {
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF;
}

u32 P0(u32 x) {
    return x ^ left_rotate(x, 9) ^ left_rotate(x, 17);
}

u32 P1(u32 x) {
    return x ^ left_rotate(x, 15) ^ left_rotate(x, 23);
}

u32 FF(u32 x, u32 y, u32 z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

u32 GG(u32 x, u32 y, u32 z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (~x & z));
}

// 初始向量
u32 IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

vector<u8> sm3_padding(const u8* msg, size_t len) {
    u64 bit_len = len * 8;
    size_t k = (448 - (bit_len + 1) % 512 + 512) % 512;
    size_t total_len = len + 1 + k / 8 + 8;

    vector<u8> padded(total_len);
    memcpy(padded.data(), msg, len);
    padded[len] = 0x80;

    for (int i = 0; i < 8; i++) {
        padded[total_len - 1 - i] = (bit_len >> (8 * i)) & 0xFF;
    }
    return padded;
}

void sm3_compress(u32 V[8], const u8* block) {
    u32 W[68], W1[64];

    for (int i = 0; i < 16; i++) {
        W[i] = (block[4 * i] << 24) | (block[4 * i + 1] << 16) |
            (block[4 * i + 2] << 8) | (block[4 * i + 3]);
    }

    for (int i = 16; i < 68; i++) {
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ left_rotate(W[i - 3], 15))
            ^ left_rotate(W[i - 13], 7) ^ W[i - 6];
    }

    for (int i = 0; i < 64; i++) {
        W1[i] = W[i] ^ W[i + 4];
    }

    u32 A = V[0], B = V[1], C = V[2], D = V[3];
    u32 E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; j++) {
        u32 SS1 = left_rotate((left_rotate(A, 12) + E + left_rotate(Tj(j), j % 32)) & 0xFFFFFFFF, 7);
        u32 SS2 = SS1 ^ left_rotate(A, 12);
        u32 TT1 = (FF(A, B, C, j) + D + SS2 + W1[j]) & 0xFFFFFFFF;
        u32 TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;

        D = C;
        C = left_rotate(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = left_rotate(F, 19);
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

vector<u8> sm3(const u8* msg, size_t len) {
    vector<u8> padded = sm3_padding(msg, len);
    u32 V[8];
    memcpy(V, IV, sizeof(IV));

    size_t block_count = padded.size() / 64;
    for (size_t i = 0; i < block_count; i++) {
        sm3_compress(V, &padded[i * 64]);
    }

    vector<u8> digest(32);
    for (int i = 0; i < 8; i++) {
        digest[4 * i] = (V[i] >> 24) & 0xFF;
        digest[4 * i + 1] = (V[i] >> 16) & 0xFF;
        digest[4 * i + 2] = (V[i] >> 8) & 0xFF;
        digest[4 * i + 3] = V[i] & 0xFF;
    }
    return digest;
}

void print_hex(const vector<u8>& data) {
    for (u8 b : data)
        cout << hex << setw(2) << setfill('0') << (int)b;
    cout << dec << endl;
}

int main() {
    string msg = "abc";

    cout << "SM3(\"abc\") = ";
    auto hash = sm3((const u8*)msg.c_str(), msg.size());
    print_hex(hash);

    // 运行效率测试
    const int N = 10000; // 测试次数
    vector<u8> test_data(64, 0x61); // 64 字节全是 'a'

    auto start = high_resolution_clock::now();

    for (int i = 0; i < N; ++i) {
        sm3(test_data.data(), test_data.size());
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start);

    cout << "运行 " << N << " 次 SM3（64字节输入）总耗时: "
        << duration.count() << " 毫秒" << endl;
    cout << "平均每次耗时: " << (double)duration.count() / N << " 毫秒" << endl;

    return 0;
}
