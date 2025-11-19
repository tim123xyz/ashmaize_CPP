#pragma once

#include "blake2.h"

#include <cstddef>
#include <cstdint>
#include <array>
#include <vector>

constexpr size_t DIGEST_SIZE = 64;
constexpr size_t SEED_SIZE = 32;
constexpr uint32_t OFFSET_LOOPS = 4;

using RomDigest = std::array<uint8_t,DIGEST_SIZE>;

struct FullRandom {};

struct TwoStep {
    size_t pre_size;
    size_t mixing_numbers;
};

struct Rom {
    RomDigest digest;
    std::vector<uint8_t> data;

    Rom(const std::vector<uint8_t> &key, const FullRandom &gen_type, size_t size);
    Rom(const std::vector<uint8_t> &key, const TwoStep &gen_type, size_t size);
    std::array<uint8_t,SEED_SIZE> get_seed(const std::vector<uint8_t> &key) const;
    const uint8_t* at(uint32_t i) const;
};

void hprime(uint8_t* output, uint32_t output_len, const uint8_t* input, uint32_t input_len);

template<size_t size>
void xorbuf(uint8_t* __restrict out, uint8_t* __restrict input) {
    for(size_t i=0; i<size; i++) {
        out[i] ^= input[i];
    }
    return;
}
