#ifndef EBPF_H
#define EBPF_H

#include <stdint.h>

/* =========================================================================
 * eBPF INSTRUCTION STRUCTURE
 * ========================================================================= */
// Every eBPF instruction is exactly 64 bits (8 bytes) long
struct ebpf_inst {
    uint8_t  opcode;    // Byte 0: The operation to execute
    uint8_t  dst_reg:4; // Byte 1 (low nibble): Destination register
    uint8_t  src_reg:4; // Byte 1 (high nibble): Source register
    int16_t  offset;    // Byte 2-3: Offset for jumps (e.g., +5 instructions)
    int32_t  imm;       // Byte 4-7: Immediate value (e.g., our 42)
};

/* =========================================================================
 * OPCODE DECODING (8 bits)
 * The eBPF opcode is composed of: [4 bits: Operation] [1 bit: Source] [3 bits: Class]
 * ========================================================================= */

// 1. CLASS EXTRACTION (Low 3 bits: mask 0x07)
#define BPF_CLASS(code) ((code) & 0x07)

#define BPF_LD    0x00  // Load (used for special 64-bit instruction)
#define BPF_LDX   0x01  // Load from memory to register
#define BPF_ST    0x02  // Store immediate to memory
#define BPF_STX   0x03  // Store from register to memory
#define BPF_ALU   0x04  // 32-bit math (e.g., int)
#define BPF_JMP   0x05  // 64-bit jumps (if/else) and exit
#define BPF_JMP32 0x06  // 32-bit jumps
#define BPF_ALU64 0x07  // 64-bit math (e.g., long)

// 2. SOURCE EXTRACTION (4th bit: mask 0x08)
#define BPF_SRC(code)   ((code) & 0x08)

#define BPF_K     0x00  // Source is the "imm" field (constant)
#define BPF_X     0x08  // Source is the "src_reg" (register)

// 3. OPERATION EXTRACTION (High 4 bits: mask 0xf0)
#define BPF_OP(code)    ((code) & 0xf0)

// Math Operations (ALU / ALU64)
#define BPF_ADD   0x00
#define BPF_SUB   0x10
#define BPF_MUL   0x20
#define BPF_DIV   0x30
#define BPF_OR    0x40
#define BPF_AND   0x50
#define BPF_NEG   0x80
#define BPF_XOR   0xa0
#define BPF_MOV   0xb0

// Jump Operations (JMP)
#define BPF_JA    0x00  // Unconditional jump (Jump Always)
#define BPF_JEQ   0x10  // Jump if equal (==)
#define BPF_JGT   0x20  // Jump if greater (>)
#define BPF_EXIT  0x90  // Terminate the program and return R0 

/* =========================================================================
 * SPECIAL INSTRUCTIONS
 * ========================================================================= */
// This is the exception to the rule: a 16-byte long instruction
// Corresponds to (BPF_LD | BPF_DW | BPF_IMM)
#define BPF_LD_IMM64 0x18 

#endif // EBPF_H
