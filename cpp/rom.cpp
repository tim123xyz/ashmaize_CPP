#include "rom.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <sodium.h>

const size_t DATASET_ACCESS_SIZE = 64;

Rom::Rom(const std::vector<uint8_t> &key, const FullRandom &gen_type, size_t size) {
    if (sodium_init() == -1) {
        throw std::runtime_error("libsodium can not init");
    }
    data.resize(size);
    std::vector<uint8_t> seed = get_seed(key);
    hprime(data, seed);
    digest.resize(64);
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, 64);
    crypto_generichash_update(&st, data.data(), data.size());
    crypto_generichash_final(&st, digest.data(), 64);
    return;
}

Rom::Rom(const std::vector<uint8_t> &key, const TwoStep &gen_type, size_t size) {
    if (sodium_init() == -1) {
        throw std::runtime_error("libsodium can not init");
    }
    data.resize(size);
    std::vector<uint8_t> seed = get_seed(key);

    std::vector<uint8_t> mixing_buffer (gen_type.pre_size);
    hprime(mixing_buffer, seed);
    crypto_generichash_state st;
    const uint32_t OFFSET_LOOPS = 4;

    std::vector<uint16_t> offsets_diff;
    for(uint32_t i=0; i<OFFSET_LOOPS; i++) {
        std::vector<uint8_t> command (64);
        crypto_generichash_init(&st, NULL, 0, 64);
        crypto_generichash_update(&st, seed.data(), 32);
        crypto_generichash_update(&st, reinterpret_cast<const uint8_t*>("generation offset"), 17);
        crypto_generichash_update(&st, reinterpret_cast<uint8_t*>(&i), 4);
        crypto_generichash_final(&st, command.data(), 64);
        offsets_diff.reserve(offsets_diff.size()+32);
        for(size_t i=0; i<64; i+=2) {
            offsets_diff.emplace_back(static_cast<uint16_t>(command[i]) | (static_cast<uint16_t>(command[i+1]) << 8));
        }
    }
    assert(offsets_diff.size() == 32*OFFSET_LOOPS);

    size_t nb_chunks_bytes = data.size() / 64;
    std::vector<uint8_t> offsets_bytes (nb_chunks_bytes, 0);

    std::vector<uint8_t> offset_bytes_input (64);
    crypto_generichash_init(&st, NULL, 0, 64);
    crypto_generichash_update(&st, seed.data(), 32);
    crypto_generichash_update(&st, reinterpret_cast<const uint8_t*>("generation offset base"), 22);
    crypto_generichash_final(&st, offset_bytes_input.data(), 64);
    hprime(offsets_bytes, offset_bytes_input);

    std::vector<uint8_t> offsets = offsets_bytes;

    crypto_generichash_init(&st, NULL, 0, 64);
    uint32_t nb_source_chunks = static_cast<uint32_t>(gen_type.pre_size / 64);
    size_t chunks = data.size() / 64;
    for(size_t i=0; i<chunks; i++) {
        uint8_t* chunk = data.data() + 64*i;

        uint32_t start_idx = offsets[i % offsets.size()] % nb_source_chunks;
        uint32_t idx0 = i % nb_source_chunks;
        size_t offset = idx0*64U;
        uint8_t* input = mixing_buffer.data()+offset;
        std::memcpy(chunk, input, 64);

        for(size_t d=1; d<gen_type.mixing_numbers; d++) {
            uint32_t idx = (start_idx + static_cast<uint32_t>(offsets_diff[(d-1) % offsets_diff.size()])) % nb_source_chunks;
            size_t offset = static_cast<size_t>(idx)*64;
            uint8_t* input = mixing_buffer.data()+offset;
            xorbuf(chunk, input);
        }

        crypto_generichash_update(&st, chunk, 64);
    }
    digest.resize(64);
    crypto_generichash_final(&st, digest.data(), 64);
    return;
}

std::vector<uint8_t> Rom::get_seed(const std::vector<uint8_t> &key) const {
    std::vector<uint8_t> res (32);
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, 32);
    uint32_t len = data.size();
    crypto_generichash_update(&st, reinterpret_cast<uint8_t*>(&len), 4);
    crypto_generichash_update(&st, key.data(), key.size());
    crypto_generichash_final(&st, res.data(), 32);
    return res; 
}

const uint8_t* Rom::at(uint32_t i) const {
    size_t start = i % (this->data.size() / DATASET_ACCESS_SIZE);
    return this->data.data() + start;
}

void xorbuf(uint8_t* out, uint8_t* input) {
    uint64_t* out64 = reinterpret_cast<uint64_t*>(out);
    uint64_t* input64 = reinterpret_cast<uint64_t*>(input);
    for(size_t i=0; i<8; i++) {
        out64[i] ^= input64[i];
    }
    return;
}

void hprime(std::vector<uint8_t> &output, const std::vector<uint8_t> &input) {
    crypto_generichash_state st;
    uint32_t output_len = output.size();
    if (output_len <= 64) {
        crypto_generichash_init(&st, NULL, 0, output.size());
        crypto_generichash_update(&st, reinterpret_cast<uint8_t*>(&output_len), 4);
        crypto_generichash_update(&st, input.data(), input.size());
        crypto_generichash_final(&st, output.data(), output.size());
        return;
    }
    std::vector<uint8_t> v0 (64);

    crypto_generichash_init(&st, nullptr, 0, 64);
    crypto_generichash_update(&st, reinterpret_cast<uint8_t*>(&output_len), 4);
    crypto_generichash_update(&st, input.data(), input.size());
    crypto_generichash_final(&st, v0.data(), 64);
    std::memcpy(output.data(), v0.data(), 32);
    size_t bytes = output_len - 32;
    size_t pos = 32;

    std::vector<uint8_t> vi_prev = v0;
    while (bytes > 64) {
        crypto_generichash_init(&st, nullptr, 0, 64);
        crypto_generichash_update(&st, vi_prev.data(), 64);
        crypto_generichash_final(&st, vi_prev.data(), 64);
        std::memcpy(output.data()+pos, vi_prev.data(), 32);

        bytes -= 32;
        pos += 32;
    }

    crypto_generichash_init(&st, nullptr, 0, bytes);
    crypto_generichash_update(&st, vi_prev.data(), vi_prev.size());
    crypto_generichash_final(&st, output.data()+pos, bytes);
    return;
}
