#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <vector>

#include "rom.h"


constexpr size_t INSTR_SIZE = 20;
constexpr size_t REGS_BITS = 5;
constexpr size_t NB_REGS = 1 << REGS_BITS;
constexpr uint8_t REGS_INDEX_MASK = NB_REGS - 1;

using Register = uint64_t;

constexpr size_t REGISTER_SIZE = sizeof(Register);
constexpr uint32_t REGISTER_BITS = static_cast<uint32_t>(REGISTER_SIZE * 8);
constexpr size_t DIGEST_WORDS = DIGEST_SIZE / REGISTER_SIZE;
constexpr uint64_t ISQRT_INITIAL_BIT = static_cast<uint64_t>(1) << (REGISTER_BITS - 2);

struct Program {
    explicit Program(uint32_t nb_instrs);
    const uint8_t* at(uint32_t i) const;
    void shuffle(const std::array<uint8_t,DIGEST_SIZE> &seed);

private:
    std::vector<uint8_t> instructions;
};

struct VM {
    VM(const RomDigest &rom_digest, uint32_t nb_instrs, const std::vector<uint8_t> &salt);
    void step(const Rom &rom);
    uint64_t sum_regs(void) const;
    void post_instructions(void);
    void execute(const Rom &rom, uint32_t instr);
    void execute_one_instruction(const Rom &rom);
    uint64_t decode_src(uint8_t &op,uint8_t &r,uint64_t &lit, const Rom &rom);
    std::array<uint8_t,DIGEST_SIZE> finalize(void);

    uint64_t mem_access64(const Rom &rom, uint32_t addr);
    uint64_t special1_value64(void);
    uint64_t special2_value64(void);

    Program program;
    std::array<Register,NB_REGS> regs;
    uint32_t ip;
    blake2b_state st;
    blake2b_state prog_digest;
    blake2b_state mem_digest;
    std::array<uint8_t,DIGEST_SIZE> prog_seed;
    std::array<uint8_t,DIGEST_SIZE> buf;
    uint32_t memory_counter;
    uint32_t loop_counter;

    uint8_t* prog_chunk;
    uint8_t opcode, op1, op2, r1, r2, r3;
    uint16_t rs;
    uint64_t lit1, lit2, src1, src2;
};

std::array<uint8_t,DIGEST_SIZE> hash(const std::vector<uint8_t> &salt, const Rom &rom, uint32_t nb_loops, uint32_t nb_instrs);

uint64_t isqrt(uint64_t n);
uint64_t rotate_left(uint64_t v, uint32_t n);
uint64_t rotate_right(uint64_t v, uint32_t n);
