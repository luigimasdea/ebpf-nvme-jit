#ifndef RISCV_H
#define RISCV_H

#include <stdint.h>

/* =========================================================================
 * RISC-V REGISTERS (LP64 ABI Convention)
 * ========================================================================= */
#define RV_REG_ZERO 0   // Hardwired to zero
#define RV_REG_RA   1   // Return Address
#define RV_REG_SP   2   // Stack Pointer

// Temporary registers
#define RV_REG_T0   5
#define RV_REG_T1   6
#define RV_REG_T2   7

// Argument and return value registers
#define RV_REG_A0   10  // Return value (Corresponds to R0 in eBPF)
#define RV_REG_A1   11  // Argument 1 (Corresponds to R1 in eBPF)
#define RV_REG_A2   12
#define RV_REG_A3   13
#define RV_REG_A4   14
#define RV_REG_A5   15

// Frame Pointer (Used for the eBPF stack)
#define RV_REG_FP   8   // Also known as s0

// Callee-saved registers (Variables that must survive function calls)
#define RV_REG_S1   9
#define RV_REG_S2   18
#define RV_REG_S3   19
#define RV_REG_S4   20


/* =========================================================================
 * RISC-V OPCODES AND FUNCT
 * ========================================================================= */

// OPCODES
#define RV_OP_IMM   0x13  // Opcode for ALU operations with Immediate (e.g., ADDI)
#define RV_OP_ALU   0x33  // Opcode for ALU operations between Registers (e.g., ADD)
#define RV_OP_IMM_32 0x1B // Opcode for ALU32 operations with Immediate (RV64)
#define RV_OP_ALU_32 0x3B // Opcode for ALU32 operations between Registers (RV64)
#define RV_OP_LUI   0x37  // Opcode for Load Upper Immediate

// FUNCT3
#define RV_F3_ADD   0x0
#define RV_F3_MUL   0x0   // Funct3 for MUL (M-extension)
#define RV_F3_SLL   0x1
#define RV_F3_SLT   0x2
#define RV_F3_SLTU  0x3
#define RV_F3_XOR   0x4
#define RV_F3_DIV   0x4   // Funct3 for DIV (M-extension)
#define RV_F3_SRL   0x5
#define RV_F3_DIVU  0x5   // Funct3 for DIVU (M-extension)
#define RV_F3_OR    0x6
#define RV_F3_REM   0x6   // Funct3 for REM (M-extension)
#define RV_F3_AND   0x7
#define RV_F3_REMU  0x7   // Funct3 for REMU (M-extension)

// FUNCT7
#define RV_F7_ADD   0x00
#define RV_F7_MUL   0x01  // Funct7 for M-extension (MUL, DIV, REM)
#define RV_F7_SUB   0x20
#define RV_F7_SRL   0x00
#define RV_F7_SRA   0x20

/* =========================================================================
 * INSTRUCTION CONSTRUCTORS (Machine Code Generation)
 * ========================================================================= */

// Generates an I-type instruction (e.g., ADDI rd, rs1, imm)
// Format: [12 bit: imm] [5 bit: rs1] [3 bit: funct3] [5 bit: rd] [7 bit: opcode]
#define RV_MAKE_I(opcode, rd, funct3, rs1, imm) \
    (uint32_t)( (((uint32_t)(imm) & 0xFFF) << 20) | (((uint32_t)(rs1) & 0x1F) << 15) | \
                (((uint32_t)(funct3) & 0x7) << 12) | (((uint32_t)(rd) & 0x1F) << 7) | ((uint32_t)(opcode) & 0x7F) )

// Generates an R-type instruction (e.g., ADD rd, rs1, rs2)
// Format: [7 bit: funct7] [5 bit: rs2] [5 bit: rs1] [3 bit: funct3] [5 bit: rd] [7 bit: opcode]
#define RV_MAKE_R(opcode, rd, funct3, rs1, rs2, funct7) \
    (uint32_t)( ((funct7 & 0x7F) << 25) | ((rs2 & 0x1F) << 20) | ((rs1 & 0x1F) << 15) | \
                ((funct3 & 0x7) << 12) | ((rd & 0x1F) << 7) | (opcode & 0x7F) )

// Generates a U-Type instruction (e.g., LUI rd, imm)
// Format: [20 bit: imm] [5 bit: rd] [7 bit: opcode]
#define RV_MAKE_U(opcode, rd, imm) \
    (uint32_t)( ((imm & 0xFFFFF) << 12) | ((rd & 0x1F) << 7) | (opcode & 0x7F) )

// Fixed pre-calculated instructions
#define RV_INST_RET 0x00008067 // jalr zero, 0(ra)

#endif // RISCV_H
