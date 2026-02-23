#include <iostream>
#include <vector>
#include <cstdint>
#include <algorithm>

worusing namespace std;

//ASE-based Pseudo-Random Generator (PRG) Implementation in C++
uint64_t mock_aes_encrypt(uint64_t seed, uint64_t counter) {
    uint64_t x = seed ^ counter;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    x = x ^ (x >> 31);
    return x;
}

vector<uint64_t> generate_prg(uint64_t seed, size_t length) {
    vector<uint64_t> output;
    for (size_t i = 0; i < length; ++i) {
        output.push_back(mock_aes_encrypt(seed, i));
    }
    return output;
}

uint64_t compute_prf(uint64_t key, uint64_t m) {
    return mock_aes_encrypt(key, m);
}

struct PRP_Result {
    uint32_t left;
    uint32_t right;
};


PRP_Result encrypt_prp(uint32_t L, uint32_t R, uint64_t master_key) {
    uint32_t round_keys[4];

    auto keys = generate_prg(master_key, 4);
    
    for (int i = 0; i < 4; ++i) {
        uint32_t temp = R;

        uint32_t f_out = static_cast<uint32_t>(compute_prf(keys[i], R));
        R = L ^ f_out;
        L = temp;
    }
    return {L, R};
}