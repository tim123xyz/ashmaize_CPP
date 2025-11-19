#include "lib.h"
#include "rom.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <vector>
#include <omp.h>

constexpr std::size_t Iterations = 100000;
constexpr std::uint32_t LoopCount = 8;
constexpr std::uint32_t InstructionCount = 256;
constexpr std::size_t RomSize = 1024 * 1024 * 1024;
constexpr std::size_t RomPreSize = 16 * 1024 * 1024;
constexpr std::size_t RomMixingNumbers = 4;
const char RomKey_str[] = "RomKey_strRomKey_strRomKey_strRomKey_strRomKey_str";
const char Salt_str[] = "Salt_strSalt_strSalt_strSalt_strSalt_str";
std::array<uint8_t,DIGEST_SIZE> correct {0xe3,0xb4,0x61,0xc7,0x4f,0x96,0xd4,0x67,0xe2,0xaa,0x10,0x72,0x0c,0x5b,0xc9,0xde,0xca,0x03,0xe5,0xaa,0xda,0xb9,0xf1,0xcf,0x01,0x9a,0xd8,0xe6,0x7e,0xd0,0xcb,0x61,0x52,0xf7,0x12,0x40,0x05,0x08,0xc1,0x06,0x38,0x99,0x0c,0x34,0xf3,0x80,0x1a,0xfa,0x2c,0x0d,0x1c,0x3f,0x87,0xad,0x06,0xac,0x04,0x01,0xc6,0xfb,0x07,0x47,0xfc,0x5d};


void print_vector(const char* label, const uint8_t* data, size_t len) {
    std::cout << label << "=";
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        if (i + 1 < len) {
            std::cout << ' ';
        }
    }
    std::cout << std::dec << std::endl;
}

void check_correctness(const std::array<uint8_t,DIGEST_SIZE> hash) {
    for(size_t i=0; i<DIGEST_SIZE; i++) {
        if(hash[i] != correct[i]) {
            throw "Hash is not Correct";
        }
    }
}

int main() {
    std::vector<uint8_t> RomKey (RomKey_str, RomKey_str+strlen(RomKey_str));
    std::vector<uint8_t> Salt (Salt_str, Salt_str+strlen(Salt_str));
    const TwoStep rom_type = TwoStep{RomPreSize, RomMixingNumbers};
    const Rom rom(RomKey, rom_type, RomSize);

    std::array<uint8_t,DIGEST_SIZE> digest = hash(Salt, rom, LoopCount, InstructionCount);
    print_vector("hash", digest.data(), digest.size());

    auto start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < Iterations/10; ++i) {
        hash(Salt, rom, LoopCount, InstructionCount);
    }
    auto stop = std::chrono::steady_clock::now();
    double total_seconds = std::chrono::duration_cast<std::chrono::duration<double>>(stop - start).count();
    double hashes_per_sec = static_cast<double>(Iterations/10) / total_seconds;
    std::cout << "Single thread:\n"
        << "Total time: " << std::fixed << std::setprecision(3) << total_seconds << " s\n"
        << "Throughput: " << std::setprecision(2) << hashes_per_sec << " hash/s\n";

    start = std::chrono::steady_clock::now();
    #pragma omp parallel for
    for (std::size_t i = 0; i < Iterations; ++i) {
        hash(Salt, rom, LoopCount, InstructionCount);
    }
    stop = std::chrono::steady_clock::now();
    total_seconds = std::chrono::duration_cast<std::chrono::duration<double>>(stop - start).count();
    hashes_per_sec = static_cast<double>(Iterations) / total_seconds;
    std::cout << "Multi threads(OpenMP):\n"
        << "Total time: " << std::fixed << std::setprecision(3) << total_seconds << " s\n"
        << "Throughput: " << std::setprecision(2) << hashes_per_sec << " hash/s\n";

    return 0;
}
