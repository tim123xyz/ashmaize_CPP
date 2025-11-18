#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

extern const size_t DATASET_ACCESS_SIZE;

using RomDigest = std::vector<uint8_t>;

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
    std::vector<uint8_t> get_seed(const std::vector<uint8_t> &key) const;
    const uint8_t* at(uint32_t i) const;
};

void xorbuf(uint8_t* out, uint8_t* input);
void hprime(std::vector<uint8_t> &output, const std::vector<uint8_t> &input);
