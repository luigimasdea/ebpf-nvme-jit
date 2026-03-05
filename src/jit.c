#include "jit.h"
#include "ebpf.h"
#include "riscv.h"
#include "utils.h"

#include <stdbool.h>

static const uint8_t bpf2rv[11] = {
    RV_REG_A0, // eBPF R0  -> RISC-V a0 (Return value)
    RV_REG_A1, // eBPF R1  -> RISC-V a1 (Argument 1)
    RV_REG_A2, // eBPF R2  -> RISC-V a2 (Argument 2)
    RV_REG_A3, // eBPF R3  -> RISC-V a3 (Argument 3)
    RV_REG_A4, // eBPF R4  -> RISC-V a4 (Argument 4)
    RV_REG_A5, // eBPF R5  -> RISC-V a5 (Argument 5)
    RV_REG_S1, // eBPF R6  -> RISC-V s1 (Callee-saved variable)
    RV_REG_S2, // eBPF R7  -> RISC-V s2 (Callee-saved variable)
    RV_REG_S3, // eBPF R8  -> RISC-V s3 (Callee-saved variable)
    RV_REG_S4, // eBPF R9  -> RISC-V s4 (Callee-saved variable)
    RV_REG_FP  // eBPF R10 -> RISC-V fp (Stack Frame Pointer - Read Only)
};

static uint32_t jit_memory[1024] __attribute__((aligned(4)));
static int pc_riscv = 0;

// Offset Map: Stores the starting RISC-V instruction index for each eBPF instruction
static uint32_t insn_offsets[256];

typedef enum {
  PASS_ANALYZE, // First pass: Calculate offsets and program size
  PASS_EMIT     // Second pass: Write RISC-V machine code to jit_memory
} jit_pass_t;

static jit_pass_t current_pass;

static void emit_rv32(uint32_t inst) {
  if (current_pass == PASS_EMIT) {
    jit_memory[pc_riscv] = inst;
  }
  pc_riscv++;
}

// Helper: Load a 32-bit immediate into a RISC-V register
// Handles the signed 12-bit limit automatically
static void emit_load_imm(uint8_t rd, int32_t imm) {
  int32_t hi = (imm + 0x800) >> 12;
  int32_t lo = imm & 0xFFF;

  emit_rv32(RV_MAKE_U(RV_OP_LUI, rd, hi));
  emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_ADD, rd, lo));
}

static void emit_alu(struct ebpf_inst inst, uint8_t rd, uint8_t rs, uint8_t f3, uint8_t f7) {
  uint8_t op = inst.opcode;
  bool is_alu64 = (BPF_CLASS(op) == BPF_ALU64);
  bool use_imm = false;

  // 1. Resolve Immediate vs Register (And handle massive immediates here!)
  if (BPF_SRC(op) == BPF_K) {
    bool is_shift = (f3 == RV_F3_SLL || f3 == RV_F3_SRL);
    int32_t max_shift = is_alu64 ? 63 : 31;

    if (is_shift && inst.imm >= 0 && inst.imm <= max_shift) {
      use_imm = true;
    }
    else if (!is_shift && inst.imm >= -2048 && inst.imm <= 2047) {
      use_imm = true;
    }
    else {
      // Immediate is too big. Load to scratch register T0.
      emit_load_imm(RV_REG_T0, inst.imm);
      rs = RV_REG_T0; // Treat the rest of the function as a register operation
    }
  }

  uint8_t op_imm = is_alu64 ? RV_OP_IMM : RV_OP_IMM_32;
  uint8_t op_alu = is_alu64 ? RV_OP_ALU : RV_OP_ALU_32;

  // 2. Clear, Linear Hardware Pathing
  if (!use_imm) {
    if (f3 == RV_F3_DIVU && f7 == RV_F7_MUL) {
      // eBPF DIV by zero returns 0. RISC-V returns -1.
      // BEQ rs, ZERO, 12 (to ADDI rd, ZERO, 0)
      emit_rv32(RV_MAKE_B(RV_OP_BRANCH, RV_F3_BEQ, rs, RV_REG_ZERO, 12));
      emit_rv32(RV_MAKE_R(op_alu, rd, f3, rd, rs, f7));
      // JAL ZERO, 8 (skip the LI 0)
      emit_rv32(RV_MAKE_J(RV_OP_JAL, RV_REG_ZERO, 8));
      emit_rv32(RV_MAKE_I(is_alu64 ? RV_OP_IMM : RV_OP_IMM_32, rd, RV_F3_ADD, RV_REG_ZERO, 0));
    } else {
      // Path A: Standard Register-to-Register (or large constant in T0)
      emit_rv32(RV_MAKE_R(op_alu, rd, f3, rd, rs, f7));
    }
  }
  else if (f7 == RV_F7_MUL) {
    // Path B: RV64M has no immediate instructions. Use T1 workaround.
    if (inst.imm == 0 && f3 == RV_F3_DIVU) {
       emit_rv32(RV_MAKE_I(is_alu64 ? RV_OP_IMM : RV_OP_IMM_32, rd, RV_F3_ADD, RV_REG_ZERO, 0));
    } else {
       emit_load_imm(RV_REG_T1, inst.imm);
       emit_rv32(RV_MAKE_R(op_alu, rd, f3, rd, RV_REG_T1, f7));
    }
  }
  else if (f7 == RV_F7_SUB) {
    // Path C: No SUBI instruction. Add the negative value.
    emit_rv32(RV_MAKE_I(op_imm, rd, RV_F3_ADD, rd, -inst.imm));
  }
  else if (f3 == RV_F3_SLL || f3 == RV_F3_SRL) {
    // Path D: Shifts pack the funct7 flag at bits [11:5] of the immediate
    // field.
    uint32_t shift_amt = (uint32_t)inst.imm & (is_alu64 ? 0x3F : 0x1F);
    uint32_t packed_imm = (f7 << 5) | shift_amt;
    emit_rv32(RV_MAKE_I(op_imm, rd, f3, rd, packed_imm));
  }
  else {
    // Path E: Standard, clean Immediate Math (ADD, AND, OR, XOR)
    emit_rv32(RV_MAKE_I(op_imm, rd, f3, rd, inst.imm & 0xFFF));
  }

  // 3. eBPF standard: 32-bit ALU operations MUST zero-extend to 64-bit.
  // RISC-V ALU_32 operations (OP-32) sign-extend the result.
  if (!is_alu64 && rd != RV_REG_ZERO) {
    emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_SLL, rd, 32));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_SRL, rd, 32));
  }
}

extern void* bpf_helper_lookup(int32_t imm);

static void emit_jmp(struct ebpf_inst inst, uint32_t target_idx) {
  uint8_t op = inst.opcode;
  uint8_t rd = (inst.dst_reg <= 10) ? bpf2rv[inst.dst_reg] : RV_REG_ZERO;
  uint8_t rs = (inst.src_reg <= 10) ? bpf2rv[inst.src_reg] : RV_REG_ZERO;
  bool is_jmp32 = (BPF_CLASS(op) == BPF_JMP32);

  if (!is_jmp32 && BPF_OP(op) == BPF_JA) {
    int32_t rv_off = 0;
    if (current_pass == PASS_EMIT) {
      rv_off = (insn_offsets[target_idx] - pc_riscv) * 4;
    }
    emit_rv32(RV_MAKE_J(RV_OP_JAL, RV_REG_ZERO, rv_off));
    return;
  }

  if (BPF_OP(op) == BPF_CALL) {
    void* func_addr = bpf_helper_lookup(inst.imm);
    if (func_addr) {
      emit_load_imm(RV_REG_T0, (uintptr_t)func_addr);
      emit_rv32(RV_MAKE_I(RV_OP_JALR, RV_REG_RA, 0, RV_REG_T0, 0));
    }
    return;
  }

  // For conditional jumps, if BPF_SRC is BPF_K, load imm to T0
  if (BPF_SRC(op) == BPF_K) {
    emit_load_imm(RV_REG_T0, inst.imm);
    rs = RV_REG_T0;
  }

  uint8_t cmp_rd = rd;
  uint8_t cmp_rs = rs;

  // For 32-bit jumps, we must truncate the 64-bit registers to 32-bit
  if (is_jmp32) {
    bool is_signed = (BPF_OP(op) == BPF_JSGT || BPF_OP(op) == BPF_JSGE ||
                      BPF_OP(op) == BPF_JSLT || BPF_OP(op) == BPF_JSLE);

    if (is_signed) {
      // Sign-extend 32-bit to 64-bit (ADDIW T1, rd, 0)
      emit_rv32(RV_MAKE_I(RV_OP_IMM_32, RV_REG_T1, RV_F3_ADD, rd, 0));
      emit_rv32(RV_MAKE_I(RV_OP_IMM_32, RV_REG_T2, RV_F3_ADD, rs, 0));
    } else {
      // Zero-extend 32-bit to 64-bit (SLLI + SRLI)
      emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SLL, rd, 32));
      emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SRL, RV_REG_T1, 32));
      emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T2, RV_F3_SLL, rs, 32));
      emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T2, RV_F3_SRL, RV_REG_T2, 32));
    }
    cmp_rd = RV_REG_T1;
    cmp_rs = RV_REG_T2;
  }

  int32_t rv_off = 0;
  if (current_pass == PASS_EMIT) {
    rv_off = (insn_offsets[target_idx] - pc_riscv) * 4;
  }

  // Handle different jump types using prepared registers
  switch (BPF_OP(op)) {
    case BPF_JEQ:  emit_rv32(RV_MAKE_B(RV_OP_BRANCH, RV_F3_BEQ, cmp_rd, cmp_rs, rv_off)); break;
    case BPF_JNE:  emit_rv32(RV_MAKE_B(RV_OP_BRANCH, RV_F3_BNE, cmp_rd, cmp_rs, rv_off)); break;
    case BPF_JGT:  emit_rv32(RV_MAKE_B(RV_OP_BRANCH, RV_F3_BLTU, cmp_rs, cmp_rd, rv_off)); break;
    case BPF_JGE:  emit_rv32(RV_MAKE_B(RV_OP_BRANCH, RV_F3_BGEU, cmp_rd, cmp_rs, rv_off)); break;
    case BPF_JLT:  emit_rv32(RV_MAKE_B(RV_OP_BRANCH, RV_F3_BLTU, cmp_rd, cmp_rs, rv_off)); break;
    case BPF_JLE:  emit_rv32(RV_MAKE_B(RV_OP_BRANCH, RV_F3_BGEU, cmp_rs, cmp_rd, rv_off)); break;
    case BPF_JSGT: emit_rv32(RV_MAKE_B(RV_OP_BRANCH, RV_F3_BLT, cmp_rs, cmp_rd, rv_off)); break;
    case BPF_JSGE: emit_rv32(RV_MAKE_B(RV_OP_BRANCH, RV_F3_BGE, cmp_rd, cmp_rs, rv_off)); break;
    case BPF_JSLT: emit_rv32(RV_MAKE_B(RV_OP_BRANCH, RV_F3_BLT, cmp_rd, cmp_rs, rv_off)); break;
    case BPF_JSLE: emit_rv32(RV_MAKE_B(RV_OP_BRANCH, RV_F3_BGE, cmp_rs, cmp_rd, rv_off)); break;
    case BPF_JSET:
      emit_rv32(RV_MAKE_R(RV_OP_ALU, RV_REG_T1, RV_F3_AND, cmp_rd, cmp_rs, RV_F7_ADD));
      if (current_pass == PASS_EMIT) {
        rv_off = (insn_offsets[target_idx] - pc_riscv) * 4;
      }
      emit_rv32(RV_MAKE_B(RV_OP_BRANCH, RV_F3_BNE, RV_REG_T1, RV_REG_ZERO, rv_off));
      break;
  }
}

static void emit_ldx(struct ebpf_inst inst) {
  uint8_t op = inst.opcode;
  uint8_t rd = (inst.dst_reg <= 10) ? bpf2rv[inst.dst_reg] : RV_REG_ZERO;
  uint8_t rs = (inst.src_reg <= 10) ? bpf2rv[inst.src_reg] : RV_REG_ZERO;
  uint8_t f3;

  switch (BPF_SIZE(op)) {
    case BPF_B:  f3 = RV_F3_LBU; break;
    case BPF_H:  f3 = RV_F3_LHU; break;
    case BPF_W:  f3 = RV_F3_LWU; break;
    case BPF_DW: f3 = RV_F3_LD; break;
    default: return;
  }

  emit_rv32(RV_MAKE_I(RV_OP_LOAD, rd, f3, rs, inst.offset));
}

static void emit_stx(struct ebpf_inst inst) {
  uint8_t op = inst.opcode;
  uint8_t rd = (inst.dst_reg <= 10) ? bpf2rv[inst.dst_reg] : RV_REG_ZERO;
  uint8_t rs = (inst.src_reg <= 10) ? bpf2rv[inst.src_reg] : RV_REG_ZERO;
  uint8_t f3;

  switch (BPF_SIZE(op)) {
    case BPF_B:  f3 = RV_F3_SB; break;
    case BPF_H:  f3 = RV_F3_SH; break;
    case BPF_W:  f3 = RV_F3_SW; break;
    case BPF_DW: f3 = RV_F3_SD; break;
    default: return;
  }

  emit_rv32(RV_MAKE_S(RV_OP_STORE, f3, rd, rs, inst.offset));
}

static void emit_st(struct ebpf_inst inst) {
  uint8_t op = inst.opcode;
  uint8_t rd = (inst.dst_reg <= 10) ? bpf2rv[inst.dst_reg] : RV_REG_ZERO;
  uint8_t f3;

  switch (BPF_SIZE(op)) {
    case BPF_B:  f3 = RV_F3_SB; break;
    case BPF_H:  f3 = RV_F3_SH; break;
    case BPF_W:  f3 = RV_F3_SW; break;
    case BPF_DW: f3 = RV_F3_SD; break;
    default: return;
  }

  // Load immediate to T0 first
  emit_load_imm(RV_REG_T0, inst.imm);
  emit_rv32(RV_MAKE_S(RV_OP_STORE, f3, rd, RV_REG_T0, inst.offset));
}

static void emit_atomic(struct ebpf_inst inst) {
  uint8_t op = inst.opcode;
  uint8_t rd = (inst.dst_reg <= 10) ? bpf2rv[inst.dst_reg] : RV_REG_ZERO;
  uint8_t rs = (inst.src_reg <= 10) ? bpf2rv[inst.src_reg] : RV_REG_ZERO;
  uint8_t f3 = (BPF_SIZE(op) == BPF_DW) ? RV_F3_AMO_D : RV_F3_AMO_W;
  uint8_t f7_op;
  bool fetch = (inst.imm & BPF_FETCH);

  switch (inst.imm & 0xF0) {
    case BPF_ADD: f7_op = RV_F7_AMOADD; break;
    case BPF_AND: f7_op = RV_F7_AMOAND; break;
    case BPF_OR:  f7_op = RV_F7_AMOOR;  break;
    case BPF_XOR: f7_op = RV_F7_AMOXOR; break;
    default: return; // Unsupported atomic op
  }

  uint8_t addr_reg = rd;
  if (inst.offset != 0) {
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T0, RV_F3_ADD, rd, inst.offset));
    addr_reg = RV_REG_T0;
  }

  // If fetch is set, rd (dest for old value) is rs. Otherwise ZERO.
  uint8_t fetch_rd = fetch ? rs : RV_REG_ZERO;
  emit_rv32(RV_MAKE_AMO(fetch_rd, addr_reg, rs, f3, f7_op));
}

static void emit_endian(struct ebpf_inst inst, uint8_t rd) {
  uint8_t op = inst.opcode;

  if (BPF_SRC(op) == BPF_TO_LE) {
    if (inst.imm == 16) {
      // Truncate to 16 bits
      emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_SLL, rd, 48));
      emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_SRL, rd, 48));
    } else if (inst.imm == 32) {
      // Truncate to 32 bits
      emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_SLL, rd, 32));
      emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_SRL, rd, 32));
    }
    return;
  }

  // BPF_TO_BE
  if (inst.imm == 16) {
    // rd = ((rd & 0xff) << 8) | ((rd & 0xff00) >> 8)
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T0, RV_F3_AND, rd, 0xff));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T0, RV_F3_SLL, RV_REG_T0, 8));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_SRL, rd, 8));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_AND, rd, 0xff));
    emit_rv32(RV_MAKE_R(RV_OP_ALU, rd, RV_F3_OR, rd, RV_REG_T0, RV_F7_ADD));
  } else if (inst.imm == 32) {
    // t0 = (rd & 0x000000ff) << 24
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T0, RV_F3_AND, rd, 0xff));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T0, RV_F3_SLL, RV_REG_T0, 24));

    // t1 = (rd & 0x0000ff00) << 8
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SRL, rd, 8));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_AND, RV_REG_T1, 0xff));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SLL, RV_REG_T1, 16));
    emit_rv32(RV_MAKE_R(RV_OP_ALU, RV_REG_T0, RV_F3_OR, RV_REG_T0, RV_REG_T1, RV_F7_ADD));

    // t1 = (rd & 0x00ff0000) >> 8
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SRL, rd, 16));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_AND, RV_REG_T1, 0xff));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SLL, RV_REG_T1, 8));
    emit_rv32(RV_MAKE_R(RV_OP_ALU, RV_REG_T0, RV_F3_OR, RV_REG_T0, RV_REG_T1, RV_F7_ADD));

    // t1 = (rd & 0xff000000) >> 24
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SRL, rd, 24));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_AND, RV_REG_T1, 0xff));

    emit_rv32(RV_MAKE_R(RV_OP_ALU, rd, RV_F3_OR, RV_REG_T0, RV_REG_T1, RV_F7_ADD));
  } else if (inst.imm == 64) {
    // Byte 0 -> Bit 56
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T0, RV_F3_AND, rd, 0xff));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T0, RV_F3_SLL, RV_REG_T0, 56));

    // Byte 1 -> Bit 48
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SRL, rd, 8));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_AND, RV_REG_T1, 0xff));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SLL, RV_REG_T1, 48));
    emit_rv32(RV_MAKE_R(RV_OP_ALU, RV_REG_T0, RV_F3_OR, RV_REG_T0, RV_REG_T1, RV_F7_ADD));

    // Byte 2 -> Bit 40
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SRL, rd, 16));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_AND, RV_REG_T1, 0xff));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SLL, RV_REG_T1, 40));
    emit_rv32(RV_MAKE_R(RV_OP_ALU, RV_REG_T0, RV_F3_OR, RV_REG_T0, RV_REG_T1, RV_F7_ADD));

    // Byte 3 -> Bit 32
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SRL, rd, 24));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_AND, RV_REG_T1, 0xff));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SLL, RV_REG_T1, 32));
    emit_rv32(RV_MAKE_R(RV_OP_ALU, RV_REG_T0, RV_F3_OR, RV_REG_T0, RV_REG_T1, RV_F7_ADD));

    // Byte 4 -> Bit 24
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SRL, rd, 32));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_AND, RV_REG_T1, 0xff));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SLL, RV_REG_T1, 24));
    emit_rv32(RV_MAKE_R(RV_OP_ALU, RV_REG_T0, RV_F3_OR, RV_REG_T0, RV_REG_T1, RV_F7_ADD));

    // Byte 5 -> Bit 16
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SRL, rd, 40));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_AND, RV_REG_T1, 0xff));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SLL, RV_REG_T1, 16));
    emit_rv32(RV_MAKE_R(RV_OP_ALU, RV_REG_T0, RV_F3_OR, RV_REG_T0, RV_REG_T1, RV_F7_ADD));

    // Byte 6 -> Bit 8
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SRL, rd, 48));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_AND, RV_REG_T1, 0xff));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SLL, RV_REG_T1, 8));
    emit_rv32(RV_MAKE_R(RV_OP_ALU, RV_REG_T0, RV_F3_OR, RV_REG_T0, RV_REG_T1, RV_F7_ADD));

    // Byte 7 -> Bit 0
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SRL, rd, 56));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_AND, RV_REG_T1, 0xff));
    emit_rv32(RV_MAKE_R(RV_OP_ALU, rd, RV_F3_OR, RV_REG_T0, RV_REG_T1, RV_F7_ADD));
  }
}

static void emit_alu_op(struct ebpf_inst inst) {
  uint8_t op = inst.opcode;
  uint8_t rd = (inst.dst_reg <= 10) ? bpf2rv[inst.dst_reg] : RV_REG_ZERO;
  uint8_t rs = (inst.src_reg <= 10) ? bpf2rv[inst.src_reg] : RV_REG_ZERO;
  bool is_alu64 = (BPF_CLASS(op) == BPF_ALU64);

  switch (BPF_OP(op)) {
  case BPF_ADD: emit_alu(inst, rd, rs, RV_F3_ADD, RV_F7_ADD); break;
  case BPF_SUB: emit_alu(inst, rd, rs, RV_F3_ADD, RV_F7_SUB); break;
  case BPF_AND: emit_alu(inst, rd, rs, RV_F3_AND, RV_F7_ADD); break;
  case BPF_OR: emit_alu(inst, rd, rs, RV_F3_OR, RV_F7_ADD); break;
  case BPF_XOR: emit_alu(inst, rd, rs, RV_F3_XOR, RV_F7_ADD); break;
  case BPF_MUL: emit_alu(inst, rd, rs, RV_F3_MUL, RV_F7_MUL); break;
  case BPF_DIV: emit_alu(inst, rd, rs, RV_F3_DIVU, RV_F7_MUL); break;
  case BPF_MOD: emit_alu(inst, rd, rs, RV_F3_REMU, RV_F7_MUL); break;
  case BPF_LSH: emit_alu(inst, rd, rs, RV_F3_SLL, RV_F7_ADD); break;
  case BPF_RSH: emit_alu(inst, rd, rs, RV_F3_SRL, RV_F7_ADD); break;
  case BPF_ARSH: emit_alu(inst, rd, rs, RV_F3_SRL, RV_F7_SRA); break;
  case BPF_MOV:
    if (BPF_SRC(op) == BPF_K) {
      if (inst.imm >= -2048 && inst.imm <= 2047) {
        emit_rv32(RV_MAKE_I(is_alu64 ? RV_OP_IMM : RV_OP_IMM_32, rd, RV_F3_ADD, RV_REG_ZERO, inst.imm));
      }
      else {
        emit_load_imm(RV_REG_T0, inst.imm);
        emit_rv32(RV_MAKE_I(is_alu64 ? RV_OP_IMM : RV_OP_IMM_32, rd, RV_F3_ADD, RV_REG_T0, 0));
      }
    }
    else {
      emit_rv32(RV_MAKE_I(is_alu64 ? RV_OP_IMM : RV_OP_IMM_32, rd, RV_F3_ADD, rs, 0));
    }
    break;
  case BPF_NEG:
    emit_rv32(RV_MAKE_R(is_alu64 ? RV_OP_ALU : RV_OP_ALU_32, rd, RV_F3_ADD, RV_REG_ZERO, rd, RV_F7_SUB));
    break;
  case BPF_END:
    emit_endian(inst, rd);
    break;
  }
}

/* =========================================================================
 * CORE INSTRUCTION EMITTER
 * ========================================================================= */
static void emit_prologue() {
  // Save ra, s0-s4. Allocate 512 bytes for eBPF stack.
  // Total stack frame: 512 (ebpf) + 64 (saved regs + padding) = 576 bytes
  // sp must be 16-byte aligned. 576 is 16*36.
  emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_SP, RV_F3_ADD, RV_REG_SP, -576));
  emit_rv32(RV_MAKE_S(RV_OP_STORE, RV_F3_SD, RV_REG_SP, RV_REG_RA, 568));
  emit_rv32(RV_MAKE_S(RV_OP_STORE, RV_F3_SD, RV_REG_SP, RV_REG_FP, 560));
  emit_rv32(RV_MAKE_S(RV_OP_STORE, RV_F3_SD, RV_REG_SP, RV_REG_S1, 552));
  emit_rv32(RV_MAKE_S(RV_OP_STORE, RV_F3_SD, RV_REG_SP, RV_REG_S2, 544));
  emit_rv32(RV_MAKE_S(RV_OP_STORE, RV_F3_SD, RV_REG_SP, RV_REG_S3, 536));
  emit_rv32(RV_MAKE_S(RV_OP_STORE, RV_F3_SD, RV_REG_SP, RV_REG_S4, 528));
  
  // Set R10 (s0) to the top of the eBPF stack (sp + 512)
  emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_FP, RV_F3_ADD, RV_REG_SP, 512));

  // Move context from a0 (C first argument) to a1 (eBPF R1)
  emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_A1, RV_F3_ADD, RV_REG_A0, 0));
}

static void emit_epilogue() {
  emit_rv32(RV_MAKE_I(RV_OP_LOAD, RV_REG_RA, RV_F3_LD, RV_REG_SP, 568));
  emit_rv32(RV_MAKE_I(RV_OP_LOAD, RV_REG_FP, RV_F3_LD, RV_REG_SP, 560));
  emit_rv32(RV_MAKE_I(RV_OP_LOAD, RV_REG_S1, RV_F3_LD, RV_REG_SP, 552));
  emit_rv32(RV_MAKE_I(RV_OP_LOAD, RV_REG_S2, RV_F3_LD, RV_REG_SP, 544));
  emit_rv32(RV_MAKE_I(RV_OP_LOAD, RV_REG_S3, RV_F3_LD, RV_REG_SP, 536));
  emit_rv32(RV_MAKE_I(RV_OP_LOAD, RV_REG_S4, RV_F3_LD, RV_REG_SP, 528));
  emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_SP, RV_F3_ADD, RV_REG_SP, 576));
  emit_rv32(RV_INST_RET);
}

// Helper: Load a 64-bit immediate into a RISC-V register
static void emit_load_imm64(uint8_t rd, uint64_t imm) {
  // LUI + ADDI for the lowest 32 bits
  int32_t low = (int32_t)(imm & 0xFFFFFFFF);
  emit_load_imm(rd, low);

  // If there are high bits, we need to shift and add
  uint32_t high = (uint32_t)(imm >> 32);
  if (high != 0) {
    // We already loaded the low 32 bits into rd.
    // However, emit_load_imm uses LUI which clears the upper bits of rd in 32-bit but sign-extends in 64-bit.
    // On RV64, LUI rd, imm sign-extends the 32-bit value.
    
    // Better way for 64-bit:
    // 1. Load high 32 bits into T1
    emit_load_imm(RV_REG_T1, high);
    // 2. Shift T1 left by 32
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T1, RV_F3_SLL, RV_REG_T1, 32));
    // 3. Zero-extend the low 32 bits we already have in rd (if they were sign-extended)
    // Actually, let's just load low 32 bits into T0, zero-extend it, and OR it.
    emit_load_imm(RV_REG_T0, low);
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T0, RV_F3_SLL, RV_REG_T0, 32));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, RV_REG_T0, RV_F3_SRL, RV_REG_T0, 32));
    
    // Combine
    emit_rv32(RV_MAKE_R(RV_OP_ALU, rd, RV_F3_OR, RV_REG_T1, RV_REG_T0, RV_F7_ADD));
  } else {
    // If high bits are 0, we still need to ensure the low bits are zero-extended if we want a 64-bit unsigned load
    // But eBPF LD_IMM64 is usually for full 64-bit.
    // emit_load_imm(rd, low) sign-extends on RV64.
    // To zero-extend:
    emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_SLL, rd, 32));
    emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_SRL, rd, 32));
  }
}

static void emit_ld_imm64(struct ebpf_inst inst, struct ebpf_inst next) {
  uint8_t rd = (inst.dst_reg <= 10) ? bpf2rv[inst.dst_reg] : RV_REG_ZERO;
  uint64_t imm = ((uint64_t)next.imm << 32) | (uint32_t)inst.imm;
  emit_load_imm64(rd, imm);
}

static void generate_insn(struct ebpf_inst inst, struct ebpf_inst next, int i) {
  uint8_t op = inst.opcode;

  switch (BPF_CLASS(op)) {
    case BPF_ALU:
    case BPF_ALU64:
      emit_alu_op(inst);
      break;
    case BPF_JMP:
      if (BPF_OP(op) == BPF_EXIT) {
        emit_epilogue();
        break;
      }
    case BPF_JMP32:
      emit_jmp(inst, i + 1 + inst.offset);
      break;
    case BPF_LDX:
      emit_ldx(inst);
      break;
    case BPF_STX:
      if (BPF_MODE(op) == BPF_ATOMIC) {
        emit_atomic(inst);
      } else {
        emit_stx(inst);
      }
      break;
    case BPF_ST:
      emit_st(inst);
      break;
    case BPF_LD:
      if (op == BPF_LD_IMM64) {
        emit_ld_imm64(inst, next);
      }
      break;
  }
}


/* =========================================================================
 * MAIN COMPILER ENTRY POINT
 * ========================================================================= */
void compile_ebpf(struct ebpf_inst *prog, int len) {
  // Pass 1: Analysis (Calculate offsets)
  current_pass = PASS_ANALYZE;
  pc_riscv = 0;

  emit_prologue();
  for (int i = 0; i < len; i++) {
    insn_offsets[i] = pc_riscv;
    struct ebpf_inst inst = prog[i];
    struct ebpf_inst next = (i + 1 < len) ? prog[i + 1] : (struct ebpf_inst){0};
    generate_insn(inst, next, i);
    if (BPF_CLASS(inst.opcode) == BPF_LD && inst.opcode == BPF_LD_IMM64) {
      i++; // Skip the second half
      insn_offsets[i] = pc_riscv; // The second half doesn't generate new RV code
    }
  }
  // Set the end offset for jumps that target the very end of the program
  insn_offsets[len] = pc_riscv;

  // Pass 2: Emission (Generate code)
  current_pass = PASS_EMIT;
  pc_riscv = 0;
  emit_prologue();
  for (int i = 0; i < len; i++) {
    struct ebpf_inst inst = prog[i];
    struct ebpf_inst next = (i + 1 < len) ? prog[i + 1] : (struct ebpf_inst){0};
    generate_insn(inst, next, i);
    if (BPF_CLASS(inst.opcode) == BPF_LD && inst.opcode == BPF_LD_IMM64) {
      i++;
    }
  }
}

uint64_t run_jit_filter(struct ebpf_inst *prog, int num_instructions, void *ctx) {
  compile_ebpf(prog, num_instructions);

  uart_print("[DEBUG] JIT Memory Dump:\n");
  for (int i = 0; i < pc_riscv; i++) {
    uart_print("  [");
    uart_print_int(i);
    uart_print("] 0x");
    uart_print_hex(jit_memory[i]);
    uart_print("\n");
  }

  asm volatile("fence.i");
  uint64_t (*filter)(void *ctx) = (uint64_t (*)(void *))jit_memory;
  return filter(ctx);
}
