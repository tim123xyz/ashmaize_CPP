#include "lib.h"
#include "rom.h"

#include <algorithm>
#include <cstring>
#include <vector>

const size_t INSTR_SIZE = 20;
const size_t REGS_BITS = 5;
const size_t NB_REGS = 1 << REGS_BITS;
const uint8_t REGS_INDEX_MASK = NB_REGS - 1;
const size_t REGISTER_SIZE = sizeof(Register);
const uint32_t REGISTER_BITS = static_cast<uint32_t>(REGISTER_SIZE * 8);
const size_t DIGEST_SIZE = 64;
const size_t DIGEST_WORDS = DIGEST_SIZE / REGISTER_SIZE;
const uint64_t ISQRT_INITIAL_BIT = static_cast<uint64_t>(1) << (REGISTER_BITS - 2);

Program::Program(uint32_t nb_instrs) {
    size_t size = nb_instrs * INSTR_SIZE;
    instructions = std::vector<uint8_t> (size);
}

const uint8_t* Program::at(uint32_t i) const {
    size_t start = (static_cast<size_t>(i)*INSTR_SIZE) % instructions.size();
    return instructions.data()+start;
}

void Program::shuffle(const std::vector<uint8_t> &seed) {
    hprime(instructions, seed);
}

VM::VM(const RomDigest &rom_digest, uint32_t nb_instrs, const std::vector<uint8_t> &salt)
    : program(nb_instrs) {
    const size_t REGS_CONTENT_SIZE = REGISTER_SIZE * NB_REGS;

    buf.resize(DIGEST_SIZE);

    std::vector<uint8_t> init_buffer (REGS_CONTENT_SIZE + 3 * DIGEST_SIZE);

    std::vector<uint8_t> init_buffer_input (DIGEST_SIZE+salt.size());
    std::memcpy(init_buffer_input.data(), rom_digest.data(), DIGEST_SIZE);
    std::memcpy(init_buffer_input.data()+DIGEST_SIZE, salt.data(), salt.size());
    hprime(init_buffer, init_buffer_input);

    regs = std::vector<Register> (NB_REGS);
    for(size_t i=0; i<regs.size(); i++) {
        regs[i] = *reinterpret_cast<const Register*>(init_buffer.data()+REGISTER_SIZE*i);
    }

    crypto_generichash_init(&prog_digest, NULL, 0, DIGEST_SIZE);
    crypto_generichash_update(&prog_digest, init_buffer.data()+REGS_CONTENT_SIZE, DIGEST_SIZE);
    crypto_generichash_init(&mem_digest, NULL, 0, DIGEST_SIZE);
    crypto_generichash_update(&mem_digest, init_buffer.data()+REGS_CONTENT_SIZE+DIGEST_SIZE, DIGEST_SIZE);
    prog_seed.resize(DIGEST_SIZE);
    std::memcpy(prog_seed.data(), init_buffer.data()+REGS_CONTENT_SIZE+2*DIGEST_SIZE, DIGEST_SIZE);

    ip = 0;
    loop_counter = 0;
    memory_counter = 0;
    return;
}

void VM::step(const Rom &rom) {
    execute_one_instruction(rom);
    ip += 1;
}

uint64_t VM::sum_regs(void) const {
    uint64_t sum = 0;
    for(const uint64_t value : regs) {
        sum += value;
    }
    return sum;
}

void VM::post_instructions(void) {
    uint64_t _sum_regs = sum_regs();

    st = prog_digest;
    crypto_generichash_update(&st, reinterpret_cast<uint8_t*>(&_sum_regs), sizeof(_sum_regs));
    crypto_generichash_final(&st, prog_seed.data(), DIGEST_SIZE);

    st = mem_digest;
    crypto_generichash_update(&st, reinterpret_cast<uint8_t*>(&_sum_regs), sizeof(_sum_regs));
    crypto_generichash_final(&st, buf.data(), DIGEST_SIZE);

    crypto_generichash_init(&st, NULL, 0, DIGEST_SIZE);
    crypto_generichash_update(&st, prog_seed.data(), DIGEST_SIZE);
    crypto_generichash_update(&st, buf.data(), DIGEST_SIZE);
    crypto_generichash_update(&st, reinterpret_cast<uint8_t*>(&loop_counter), 4);
    crypto_generichash_final(&st, buf.data(), DIGEST_SIZE);
    std::vector<uint8_t> mixing_out (NB_REGS * REGISTER_SIZE * 32);
    hprime(mixing_out, buf);

    for(size_t i=0; i<mixing_out.size(); i+=NB_REGS * REGISTER_SIZE) {
        for(size_t j=0; j<regs.size(); j++) {
            regs[j] ^= *reinterpret_cast<const Register*>(mixing_out.data()+i+REGISTER_SIZE*j);
        }
    }

    loop_counter += 1;
    return;
}


void VM::execute(const Rom &rom, uint32_t instr) {
    program.shuffle(prog_seed);
    for(uint32_t i=0; i<instr; i++) {
        step(rom);
    }
    post_instructions();
    return;
}

std::vector<uint8_t> VM::finalize(void) {
    crypto_generichash_init(&st, NULL, 0, DIGEST_SIZE);
    crypto_generichash_final(&prog_digest, buf.data(), DIGEST_SIZE);
    crypto_generichash_update(&st, buf.data(), DIGEST_SIZE);
    crypto_generichash_final(&mem_digest, buf.data(), DIGEST_SIZE);
    crypto_generichash_update(&st, buf.data(), DIGEST_SIZE);
    crypto_generichash_update(&st, reinterpret_cast<uint8_t*>(&memory_counter), 4);
    for(Register &r : regs) {
        crypto_generichash_update(&st, reinterpret_cast<uint8_t*>(&r), REGISTER_SIZE);
    }
    std::vector<uint8_t> res (DIGEST_SIZE);
    crypto_generichash_final(&st, res.data(), DIGEST_SIZE);
    return res;
}

uint64_t VM::decode_src(uint8_t &op,uint8_t &r,uint64_t &lit, const Rom &rom) {
    switch (op) {
        case 0 ... 4:
            return regs[r]; 
        case 5 ... 8:
            return mem_access64(rom, lit);
        case 9 ... 12:
            return lit;
        case 13:
            return special1_value64();
        default:
            return special2_value64();
    }
}

void VM::execute_one_instruction(const Rom &rom) {
    prog_chunk = const_cast<uint8_t*>(program.at(ip));
    opcode = prog_chunk[0];
    op1 = prog_chunk[1] >> 4;
    op2 = prog_chunk[1] & 0x0f;
    
    rs = (static_cast<uint16_t>(prog_chunk[2]) << 8) | (static_cast<uint16_t>(prog_chunk[3]));
    r1 = static_cast<uint8_t>(rs >> (2*REGS_BITS)) & REGS_INDEX_MASK;
    r2 = static_cast<uint8_t>(rs >> REGS_BITS) & REGS_INDEX_MASK;
    r3 = static_cast<uint8_t>(rs) & REGS_INDEX_MASK;

    std::memcpy(&lit1, prog_chunk+4, REGISTER_SIZE);
    std::memcpy(&lit2, prog_chunk+12, REGISTER_SIZE);
    src1 = decode_src(op1, r1, lit1, rom);
    switch (opcode) {
        case 0 ... 39:
            src2 = decode_src(op2, r2, lit2, rom);
            regs[r3] = src1 + src2;
            break;
        case 40 ... 79:
            src2 = decode_src(op2, r2, lit2, rom);
            regs[r3] = src1 * src2;
            break;
        case 80 ... 95:
            src2 = decode_src(op2, r2, lit2, rom);
            regs[r3] = static_cast<__uint128_t>(src1)*static_cast<__uint128_t>(src2) >> REGISTER_BITS;
            break;
        case 96 ... 111:
            src2 = decode_src(op2, r2, lit2, rom);
            regs[r3] = src2 ? (src1 / src2) : special1_value64();
            break;
        case 112 ... 127:
            src2 = decode_src(op2, r2, lit2, rom);
            regs[r3] = src2 ? (src1 / src2) : special1_value64();
            break;
        case 128 ... 137:
            regs[r3] = isqrt(src1);
            break;
        case 138 ... 147:
            regs[r3] = __builtin_bitreverse64(src1);
            break;
        case 148 ... 187:
            src2 = decode_src(op2, r2, lit2, rom);
            regs[r3] = src1 ^ src2;
            break;
        case 188 ... 203:
            regs[r3] = rotate_left(src1,r1);
            break;
        case 204 ... 219:
            regs[r3] = rotate_right(src1,r1);
            break;
        case 220 ... 239:
            regs[r3] = ~src1;
            break;
        case 240 ... 247:
            src2 = decode_src(op2, r2, lit2, rom);
            regs[r3] = src1 & src2;
            break;
        case 248 ... 255:
            src2 = decode_src(op2, r2, lit2, rom);
            crypto_generichash_init(&st, NULL, 0, DIGEST_SIZE);
            crypto_generichash_update(&st, reinterpret_cast<uint8_t*>(&src1), REGISTER_SIZE);
            crypto_generichash_update(&st, reinterpret_cast<uint8_t*>(&src2), REGISTER_SIZE);
            crypto_generichash_final(&st, buf.data(), DIGEST_SIZE);
            std::memcpy(regs.data()+r3, buf.data()+REGISTER_SIZE*(opcode-248), REGISTER_SIZE);
            break;
    }
    crypto_generichash_update(&prog_digest, prog_chunk, INSTR_SIZE);
}

std::vector<uint8_t> hash(const std::vector<uint8_t> &salt, const Rom &rom, uint32_t nb_loops, uint32_t nb_instrs) {
    VM vm(rom.digest, nb_instrs, salt);
    for(uint32_t i=0; i<nb_loops; i++) {
        vm.execute(rom, nb_instrs);
    }
    std::vector<uint8_t> res = vm.finalize();
    return res;
}

uint64_t isqrt(uint64_t n) {
    uint64_t res = 0;
    uint64_t bit = ISQRT_INITIAL_BIT;
    while (bit > n) bit >>= 2;
    while (bit != 0) {
        if (n >= res + bit) {
            n -= res + bit;
            res = (res >> 1) + bit;
        } else {
            res >>= 1;
        }
        bit >>= 2;
    }
    return res;
}

uint64_t VM::mem_access64(const Rom &rom, uint32_t addr) {
    const uint8_t* mem = rom.at(addr);
    crypto_generichash_update(&mem_digest, mem, DATASET_ACCESS_SIZE);
    memory_counter += 1;

    const size_t lanes = DATASET_ACCESS_SIZE / REGISTER_SIZE;
    const size_t idx = (memory_counter % lanes) * REGISTER_SIZE;
    return *reinterpret_cast<const Register*>(mem + idx);
}

uint64_t VM::special1_value64(void) {
    st = prog_digest;
    crypto_generichash_final(&st, buf.data(), DIGEST_SIZE);
    return *reinterpret_cast<Register*>(buf.data());
}

uint64_t VM::special2_value64(void) {
    st = mem_digest;
    crypto_generichash_final(&st, buf.data(), DIGEST_SIZE);
    return *reinterpret_cast<Register*>(buf.data());
}

uint64_t rotate_left(uint64_t value, uint32_t n) {
    return (value << n) | (value >> (64 - n));
}

uint64_t rotate_right(uint64_t value, uint32_t n) {
    return (value >> n) | (value << (64 - n));
}
