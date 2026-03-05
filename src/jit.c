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
    // Path A: Standard Register-to-Register (or large constant in T0)
    emit_rv32(RV_MAKE_R(op_alu, rd, f3, rd, rs, f7));
  }
  else if (f7 == RV_F7_MUL) {
    // Path B: RV64M has no immediate instructions. Use T1 workaround.
    emit_load_imm(RV_REG_T1, inst.imm);
    emit_rv32(RV_MAKE_R(op_alu, rd, f3, rd, RV_REG_T1, f7));
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
}

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
    case BPF_CALL:
      emit_rv32(0x00000013); // nop
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
  case BPF_DIV: emit_alu(inst, rd, rs, RV_F3_DIV, RV_F7_MUL); break;
  case BPF_MOD: emit_alu(inst, rd, rs, RV_F3_REM, RV_F7_MUL); break;
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

static void generate_insn(struct ebpf_inst inst, int i) {
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
      emit_stx(inst);
      break;
    case BPF_ST:
      emit_st(inst);
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
    generate_insn(prog[i], i);
  }
  // Set the end offset for jumps that target the very end of the program
  insn_offsets[len] = pc_riscv;

  // Pass 2: Emission (Generate code)
  current_pass = PASS_EMIT;
  pc_riscv = 0;
  emit_prologue();
  for (int i = 0; i < len; i++) {
    generate_insn(prog[i], i);
  }
}

int run_jit_filter(struct ebpf_inst *prog, int num_instructions) {
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
  int (*filter)() = (int (*)())jit_memory;
  return filter();
}
