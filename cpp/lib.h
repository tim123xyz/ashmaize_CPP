#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include <sodium.h>

#include "rom.h"

extern const size_t INSTR_SIZE;
extern const size_t REGS_BITS;
extern const size_t NB_REGS;
extern const uint8_t REGS_INDEX_MASK;

using Register = uint64_t;

extern const size_t REGISTER_SIZE;
extern const uint32_t REGISTER_BITS;
extern const size_t DIGEST_SIZE;
extern const size_t DIGEST_WORDS;
extern const uint64_t ISQRT_INITIAL_BIT;

struct Program {
    explicit Program(uint32_t nb_instrs);
    const uint8_t* at(uint32_t i) const;
    void shuffle(const std::vector<uint8_t> &seed);

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
    std::vector<uint8_t> finalize(void);

    uint64_t mem_access64(const Rom &rom, uint32_t addr);
    uint64_t special1_value64(void);
    uint64_t special2_value64(void);

    Program program;
    std::vector<Register> regs;
    uint32_t ip;
    crypto_generichash_state st;
    crypto_generichash_state prog_digest;
    crypto_generichash_state mem_digest;
    std::vector<uint8_t> prog_seed;
    std::vector<uint8_t> buf;
    uint32_t memory_counter;
    uint32_t loop_counter;

    uint8_t* prog_chunk;
    uint8_t opcode, op1, op2, r1, r2, r3;
    uint16_t rs;
    uint64_t lit1, lit2, src1, src2;
};

std::vector<uint8_t> hash(const std::vector<uint8_t> &salt, const Rom &rom, uint32_t nb_loops, uint32_t nb_instrs);

uint64_t isqrt(uint64_t n);
uint64_t rotate_left(uint64_t v, uint32_t n);
uint64_t rotate_right(uint64_t v, uint32_t n);
