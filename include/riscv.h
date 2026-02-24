#ifndef RISCV_H
#define RISCV_H

#include <stdint.h>

/* =========================================================================
 * REGISTRI RISC-V (Convenzione ABI LP64)
 * ========================================================================= */
#define RV_REG_ZERO 0   // Cablato a zero hardware
#define RV_REG_RA   1   // Indirizzo di ritorno (Return Address)
#define RV_REG_SP   2   // Stack Pointer

// Temporary
#define RV_REG_T0   5
#define RV_REG_T1   6
#define RV_REG_T2   7

// Registri per argomenti e valori di ritorno
#define RV_REG_A0   10  // Valore di ritorno (Corrisponde a R0 in eBPF)
#define RV_REG_A1   11  // Argomento 1 (Corrisponde a R1 in eBPF)
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
 * OPCODES E FUNCT RISC-V
 * ========================================================================= */

// OPCODES
#define RV_OP_IMM   0x13  // Opcode per operazioni ALU con Immediato (es. ADDI)
#define RV_OP_ALU   0x33  // Opcode per operazioni ALU tra Registri (es. ADD)
#define RV_OP_LUI   0x37  // Opcode for Load Upper Immediate

// FUNCT3
#define RV_F3_ADD   0x0
#define RV_F3_OR    0x6
#define RV_F3_AND   0x7

//FUNCT7
#define RV_F7_ADD   0x00
#define RV_F7_SUB   0x20
#define RV_F7_OR    0x00
#define RV_F7_AND    0x00

/* =========================================================================
 * COSTRUTTORI DI ISTRUZIONI (Generazione Codice Macchina)
 * ========================================================================= */

// Genera un'istruzione di tipo I (es. ADDI rd, rs1, imm)
// Formato: [12 bit: imm] [5 bit: rs1] [3 bit: funct3] [5 bit: rd] [7 bit: opcode]
#define RV_MAKE_I(opcode, rd, funct3, rs1, imm) \
    (uint32_t)( ((imm & 0xFFF) << 20) | ((rs1 & 0x1F) << 15) | \
                ((funct3 & 0x7) << 12) | ((rd & 0x1F) << 7) | (opcode & 0x7F) )

// Genera un'istruzione di tipo R (es. ADD rd, rs1, rs2)
// Formato: [7 bit: funct7] [5 bit: rs2] [5 bit: rs1] [3 bit: funct3] [5 bit: rd] [7 bit: opcode]
#define RV_MAKE_R(opcode, rd, funct3, rs1, rs2, funct7) \
    (uint32_t)( ((funct7 & 0x7F) << 25) | ((rs2 & 0x1F) << 20) | ((rs1 & 0x1F) << 15) | \
                ((funct3 & 0x7) << 12) | ((rd & 0x1F) << 7) | (opcode & 0x7F) )

// Generates a U-Type instruction (e.g., LUI rd, imm)
// Format: [20 bit: imm] [5 bit: rd] [7 bit: opcode]
#define RV_MAKE_U(opcode, rd, imm) \
    (uint32_t)( ((imm & 0xFFFFF) << 12) | ((rd & 0x1F) << 7) | (opcode & 0x7F) )

// Istruzioni fisse pre-calcolate
#define RV_INST_RET 0x00008067 // jalr zero, 0(ra)

#endif // RISCV_H
