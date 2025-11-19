#include "lib.h"

#include <algorithm>
#include <cstring>
#include <array>
#include <vector>

Program::Program(uint32_t nb_instrs) {
    size_t size = nb_instrs * INSTR_SIZE;
    instructions = std::vector<uint8_t> (size);
}

const uint8_t* Program::at(uint32_t i) const {
    size_t start = (static_cast<size_t>(i)*INSTR_SIZE) % instructions.size();
    return instructions.data()+start;
}

void Program::shuffle(const std::array<uint8_t,DIGEST_SIZE> &seed) {
    hprime(instructions.data(), instructions.size(), seed.data(), seed.size());
}

VM::VM(const RomDigest &rom_digest, uint32_t nb_instrs, const std::vector<uint8_t> &salt)
    : program(nb_instrs) {
    constexpr size_t REGS_CONTENT_SIZE = REGISTER_SIZE * NB_REGS;

    std::array<uint8_t,REGS_CONTENT_SIZE + 3*DIGEST_SIZE> init_buffer;

    std::vector<uint8_t> init_buffer_input (DIGEST_SIZE+salt.size());
    std::memcpy(init_buffer_input.data(), rom_digest.data(), DIGEST_SIZE);
    std::memcpy(init_buffer_input.data()+DIGEST_SIZE, salt.data(), salt.size());
    hprime(init_buffer.data(), init_buffer.size(), init_buffer_input.data(), init_buffer_input.size());

    std::memcpy(regs.data(), init_buffer.data(), REGISTER_SIZE*regs.size());

    blake2b_init(&prog_digest, DIGEST_SIZE);
    blake2b_update(&prog_digest, init_buffer.data()+REGS_CONTENT_SIZE, DIGEST_SIZE);
    blake2b_init(&mem_digest, DIGEST_SIZE);
    blake2b_update(&mem_digest, init_buffer.data()+REGS_CONTENT_SIZE+DIGEST_SIZE, DIGEST_SIZE);
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
    blake2b_update(&st, &_sum_regs, sizeof(_sum_regs));
    blake2b_final(&st, prog_seed.data(), prog_seed.size());

    st = mem_digest;
    blake2b_update(&st, &_sum_regs, sizeof(_sum_regs));
    blake2b_final(&st, buf.data(), DIGEST_SIZE);

    blake2b_init(&st, DIGEST_SIZE);
    blake2b_update(&st, prog_seed.data(), prog_seed.size());
    blake2b_update(&st, buf.data(), DIGEST_SIZE);
    blake2b_update(&st, &loop_counter, sizeof(loop_counter));
    blake2b_final(&st, buf.data(), DIGEST_SIZE);
    std::array<uint8_t,NB_REGS*REGISTER_SIZE*32> mixing_out;
    hprime(mixing_out.data(), mixing_out.size(), buf.data(), buf.size());

    uint8_t* __restrict out = reinterpret_cast<uint8_t*>(regs.data());
    uint8_t* __restrict base = mixing_out.data();
    for(size_t i=0; i<32; i++) {
        xorbuf<NB_REGS*REGISTER_SIZE>(out, base);
        base += NB_REGS*REGISTER_SIZE;
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

std::array<uint8_t,DIGEST_SIZE> VM::finalize(void) {
    blake2b_init(&st, DIGEST_SIZE);
    blake2b_final(&prog_digest, buf.data(), DIGEST_SIZE);
    blake2b_update(&st, buf.data(), DIGEST_SIZE);
    blake2b_final(&mem_digest, buf.data(), DIGEST_SIZE);
    blake2b_update(&st, buf.data(), DIGEST_SIZE);
    blake2b_update(&st, &memory_counter, sizeof(memory_counter));
    blake2b_update(&st, regs.data(), REGISTER_SIZE*regs.size());
    std::array<uint8_t,DIGEST_SIZE> res;
    blake2b_final(&st, res.data(), res.size());
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

    rs = (static_cast<uint16_t>(prog_chunk[2]) << 8) | (static_cast<uint16_t>(prog_chunk[3])); // bswap not memcpy
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
            blake2b_init(&st, DIGEST_SIZE);
            blake2b_update(&st, &src1, REGISTER_SIZE);
            blake2b_update(&st, &src2, REGISTER_SIZE);
            blake2b_final(&st, buf.data(), DIGEST_SIZE);
            std::memcpy(regs.data()+r3, buf.data()+REGISTER_SIZE*(opcode-248), REGISTER_SIZE);
            break;
    }
    blake2b_update(&prog_digest, prog_chunk, INSTR_SIZE);
}

std::array<uint8_t,DIGEST_SIZE> hash(const std::vector<uint8_t> &salt, const Rom &rom, uint32_t nb_loops, uint32_t nb_instrs) {
    VM vm(rom.digest, nb_instrs, salt);
    for(uint32_t i=0; i<nb_loops; i++) {
        vm.execute(rom, nb_instrs);
    }
    std::array<uint8_t,DIGEST_SIZE> res = vm.finalize();
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
    blake2b_update(&mem_digest, mem, DIGEST_SIZE);
    memory_counter += 1;

    const size_t lanes = DIGEST_SIZE / REGISTER_SIZE;
    const size_t idx = (memory_counter % lanes) * REGISTER_SIZE;
    return *reinterpret_cast<const Register*>(mem + idx);
}

uint64_t VM::special1_value64(void) {
    st = prog_digest;
    blake2b_final(&st, buf.data(), DIGEST_SIZE);
    return *reinterpret_cast<Register*>(buf.data());
}

uint64_t VM::special2_value64(void) {
    st = mem_digest;
    blake2b_final(&st, buf.data(), DIGEST_SIZE);
    return *reinterpret_cast<Register*>(buf.data());
}

uint64_t rotate_left(uint64_t value, uint32_t n) {
    return (value << n) | (value >> (64 - n));
}

uint64_t rotate_right(uint64_t value, uint32_t n) {
    return (value >> n) | (value << (64 - n));
}
