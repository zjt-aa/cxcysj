#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <chrono>
#include <immintrin.h>

using namespace std;
using namespace std::chrono;

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

static const u32 IV[8] = {
    0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
    0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E
};

inline u32 Tj_scalar(int j) { return (j < 16) ? 0x79CC4519 : 0x7A879D8A; }

inline __m256i Tj_vec(int j) {
    u32 t = Tj_scalar(j);
    return _mm256_set1_epi32((int)t);
}

inline __m256i rotl32(__m256i x, int n) {
    return _mm256_or_si256(_mm256_slli_epi32(x, n),
        _mm256_srli_epi32(x, 32 - n));
}

inline __m256i P0_vec(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(x, rotl32(x, 9)), rotl32(x, 17));
}

inline __m256i P1_vec(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(x, rotl32(x, 15)), rotl32(x, 23));
}

inline __m256i FF_vec(__m256i x, __m256i y, __m256i z, int j) {
    if (j < 16) return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
    __m256i t1 = _mm256_and_si256(x, y), t2 = _mm256_and_si256(x, z), t3 = _mm256_and_si256(y, z);
    return _mm256_or_si256(_mm256_or_si256(t1, t2), t3);
}

inline __m256i GG_vec(__m256i x, __m256i y, __m256i z, int j) {
    if (j < 16) return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
    __m256i t1 = _mm256_and_si256(x, y);
    __m256i t2 = _mm256_andnot_si256(x, z);
    return _mm256_or_si256(t1, t2);
}

void sm3_4way_compress(__m256i V[8], const u8* blocks[4]) {
    __m256i W[68], W1[64];
    // load W0-15 for each lane
    for (int j = 0; j < 16; j++) {
        u32 w0 = (blocks[0][4 * j] << 24) | (blocks[0][4 * j + 1] << 16) | (blocks[0][4 * j + 2] << 8) | (blocks[0][4 * j + 3]);
        u32 w1 = (blocks[1][4 * j] << 24) | (blocks[1][4 * j + 1] << 16) | (blocks[1][4 * j + 2] << 8) | (blocks[1][4 * j + 3]);
        u32 w2 = (blocks[2][4 * j] << 24) | (blocks[2][4 * j + 1] << 16) | (blocks[2][4 * j + 2] << 8) | (blocks[2][4 * j + 3]);
        u32 w3 = (blocks[3][4 * j] << 24) | (blocks[3][4 * j + 1] << 16) | (blocks[3][4 * j + 2] << 8) | (blocks[3][4 * j + 3]);
        W[j] = _mm256_setr_epi32(w0, w1, w2, w3);
    }
    for (int j = 16; j < 68; j++) {
        __m256i wj16 = W[j - 16], wj9 = W[j - 9], wj3 = rotl32(W[j - 3], 15);
        __m256i tmp = _mm256_xor_si256(_mm256_xor_si256(wj16, wj9), wj3);
        __m256i part = _mm256_xor_si256(tmp, rotl32(W[j - 13], 7));
        W[j] = _mm256_xor_si256(_mm256_xor_si256(P1_vec(tmp), rotl32(W[j - 13], 7)), W[j - 6]);
    }
    for (int j = 0; j < 64; j++) {
        W1[j] = _mm256_xor_si256(W[j], W[j + 4]);
    }

    __m256i A = V[0], B = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
    for (int j = 0; j < 64; j++) {
        __m256i SS1 = rotl32(_mm256_add_epi32(_mm256_add_epi32(rotl32(A, 12), E), _mm256_add_epi32(Tj_vec(j), rotl32(A, 12))), 7);
        __m256i SS2 = _mm256_xor_si256(SS1, rotl32(A, 12));
        __m256i TT1 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(FF_vec(A, B, C, j), D), SS2), W1[j]);
        __m256i TT2 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(GG_vec(E, F, G, j), H), SS1), W[j]);

        D = C;
        C = rotl32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = rotl32(F, 19);
        F = E;
        E = P0_vec(TT2);
    }
    V[0] = _mm256_xor_si256(V[0], A);
    V[1] = _mm256_xor_si256(V[1], B);
    V[2] = _mm256_xor_si256(V[2], C);
    V[3] = _mm256_xor_si256(V[3], D);
    V[4] = _mm256_xor_si256(V[4], E);
    V[5] = _mm256_xor_si256(V[5], F);
    V[6] = _mm256_xor_si256(V[6], G);
    V[7] = _mm256_xor_si256(V[7], H);
}

vector<vector<u8>> sm3_4way(const vector<vector<u8>>& msgs) {
    size_t n = msgs.size();
    size_t chunk = n / 4;
    vector<vector<u8>> out(n, vector<u8>(32));
    for (size_t i = 0; i < chunk; i++) {
        const u8* blocks[4] = { msgs[4 * i + 0].data(), msgs[4 * i + 1].data(),
                               msgs[4 * i + 2].data(), msgs[4 * i + 3].data() };
        __m256i V[8];
        for (int k = 0; k < 8; k++) V[k] = _mm256_set1_epi32((int)IV[k]);
        sm3_4way_compress(V, blocks);
        u32 tmp[4][8];
        for (int k = 0; k < 8; k++) _mm256_storeu_si256((__m256i*)tmp[k], V[k]);
        for (int lane = 0; lane < 4; lane++) {
            for (int k = 0; k < 8; k++) {
                u32 v = tmp[lane][k];
                out[4 * i + lane][4 * k + 0] = (v >> 24) & 0xFF;
                out[4 * i + lane][4 * k + 1] = (v >> 16) & 0xFF;
                out[4 * i + lane][4 * k + 2] = (v >> 8) & 0xFF;
                out[4 * i + lane][4 * k + 3] = v & 0xFF;
            }
        }
    }
    return out;
}


int main() {
    vector<vector<u8>> inputs(4, vector<u8>(64, 0));
    memcpy(inputs[0].data(), "abc", 3);
    auto out = sm3_4way(inputs);
    for (int i = 0; i < 4; i++) {
        for (u8 b : out[i]) cout << hex << setw(2) << setfill('0') << (int)b;
        cout << dec << "\n";
    }
}
