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

void print_vector(const char* label, const std::vector<uint8_t> &data) {
    print_vector(label, data.data(), data.size());
}

int main() {
    std::vector<uint8_t> RomKey (RomKey_str, RomKey_str+strlen(RomKey_str));
    std::vector<uint8_t> Salt (Salt_str, Salt_str+strlen(Salt_str));
    const TwoStep rom_type = TwoStep{RomPreSize, RomMixingNumbers};
    const Rom rom(RomKey, rom_type, RomSize);

    std::vector<uint8_t> digest = hash(Salt, rom, LoopCount, InstructionCount);
    print_vector("hash", digest);

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
