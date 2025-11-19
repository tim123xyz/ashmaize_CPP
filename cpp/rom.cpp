#include "rom.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <stdexcept>
#include <vector>

Rom::Rom(const std::vector<uint8_t> &key, const FullRandom &gen_type, size_t size) {
    data.resize(size);
    std::array<uint8_t,SEED_SIZE> seed = get_seed(key);
    hprime(data.data(), data.size(), seed.data(), seed.size());
    blake2b_state st;
    blake2b_init(&st, digest.size());
    blake2b_update(&st, data.data(), data.size());
    blake2b_final(&st, digest.data(), digest.size());
    return;
}

Rom::Rom(const std::vector<uint8_t> &key, const TwoStep &gen_type, size_t size) {
    data.resize(size);
    std::array<uint8_t,SEED_SIZE> seed = get_seed(key);

    std::vector<uint8_t> mixing_buffer (gen_type.pre_size);
    hprime(mixing_buffer.data(), mixing_buffer.size(), seed.data(), seed.size());
    blake2b_state st;

    std::array<uint16_t, OFFSET_LOOPS*32> offsets_diff;
    blake2b_init(&st, DIGEST_SIZE);
    blake2b_update(&st, seed.data(), seed.size());
    blake2b_update(&st, "generation offset", 17);
    blake2b_state st2;
    for(uint32_t i=0; i<OFFSET_LOOPS; i++) {
        st2 = st;
        blake2b_update(&st2, &i, sizeof(i));
        blake2b_final(&st2, offsets_diff.data()+i*32, DIGEST_SIZE);
    }

    size_t chunks = data.size() / DIGEST_SIZE;
    std::vector<uint8_t> offsets_bytes (chunks);

    std::array<uint8_t,DIGEST_SIZE> offset_bytes_input;
    blake2b_init(&st, offset_bytes_input.size());
    blake2b_update(&st, seed.data(), seed.size());
    blake2b_update(&st, "generation offset base", 22);
    blake2b_final(&st, offset_bytes_input.data(), offset_bytes_input.size());
    hprime(offsets_bytes.data(), offsets_bytes.size(), offset_bytes_input.data(), offset_bytes_input.size());

    blake2b_init(&st, DIGEST_SIZE);
    uint32_t nb_source_chunks = gen_type.pre_size / DIGEST_SIZE;
    
    for(size_t i=0; i<chunks; i++) {
        uint8_t* chunk = data.data() + DIGEST_SIZE*i;

        uint32_t start_idx = offsets_bytes[i % offsets_bytes.size()] % nb_source_chunks;
        uint8_t* input = mixing_buffer.data()+(i % nb_source_chunks)* DIGEST_SIZE;
        std::memcpy(chunk, input, DIGEST_SIZE);

        size_t true_mixing_number = gen_type.mixing_numbers - 1;
        for(size_t d=0; d<true_mixing_number; d++) {
            size_t idx = (start_idx + offsets_diff[d % offsets_diff.size()]) % nb_source_chunks;
            uint8_t* input = mixing_buffer.data()+ DIGEST_SIZE * idx;
            xorbuf<DIGEST_SIZE>(chunk, input);
        }

        blake2b_update(&st, chunk, DIGEST_SIZE);
    }
    blake2b_final(&st, digest.data(), digest.size());
    return;
}

std::array<uint8_t,SEED_SIZE> Rom::get_seed(const std::vector<uint8_t> &key) const {
    std::array<uint8_t,SEED_SIZE> res;
    blake2b_state st;
    blake2b_init(&st, res.size());
    uint32_t len = data.size();
    blake2b_update(&st, &len, sizeof(len));
    blake2b_update(&st, key.data(), key.size());
    blake2b_final(&st, res.data(), res.size());
    return res; 
}

const uint8_t* Rom::at(uint32_t i) const {
    return data.data() + i % (data.size() / DIGEST_SIZE);
}

void hprime(uint8_t* output, uint32_t output_len, const uint8_t* input, uint32_t input_len) {
    blake2b_state st;
    if (output_len <= 64) {
        blake2b_init(&st, output_len);
        blake2b_update(&st, &output_len, sizeof(output_len));
        blake2b_update(&st, input, input_len);
        blake2b_final(&st, output, output_len);
        return;
    }
    std::array<uint8_t,64> v0;

    blake2b_init(&st, 64);
    blake2b_update(&st, &output_len, sizeof(output_len));
    blake2b_update(&st, input, input_len);
    blake2b_final(&st, v0.data(), v0.size());
    std::memcpy(output, v0.data(), 32);
    size_t bytes = output_len - 32;
    size_t pos = 32;

    while (bytes > 64) {
        blake2b_init(&st, 64);
        blake2b_update(&st, v0.data(), 64);
        blake2b_final(&st, v0.data(), 64);
        std::memcpy(output+pos, v0.data(), 32);

        bytes -= 32;
        pos += 32;
    }

    blake2b_init(&st, bytes);
    blake2b_update(&st, v0.data(), v0.size());
    blake2b_final(&st, output+pos, bytes);
    return;
}
