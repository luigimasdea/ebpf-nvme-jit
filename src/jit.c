#include "jit.h"
#include "ebpf.h"
#include "riscv.h"
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

uint32_t jit_memory[1024] __attribute__((aligned(4)));
int pc_riscv = 0;

void emit_rv32(uint32_t inst) {
  jit_memory[pc_riscv] = inst;
  pc_riscv++;
}

// Helper: Load a 32-bit immediate into a RISC-V register
// Handles the signed 12-bit limit automatically
void emit_load_imm(uint8_t rd, int32_t imm) {
  // Requires U-Type LUI + I-Type ADDI
  int32_t hi = (imm + 0x800) >> 12;
  int32_t lo = imm & 0xFFF;

  emit_rv32(RV_MAKE_U(RV_OP_LUI, rd, hi));
  emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_ADD, rd, lo));
}

// Helper: Emit a generic ALU instruction (Register or Immediate)
void emit_alu_generic(uint8_t rd, uint8_t rs, int32_t imm, bool use_imm, uint8_t f3, uint8_t f7) {
  if (use_imm) {
    // Note: RISC-V has no SUBI. We use ADDI with -imm.
    if (f7 == RV_F7_SUB) {
      emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_ADD, rd, -imm));
    } else {
      emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, f3, rd, imm));
    }
  } else {
    emit_rv32(RV_MAKE_R(RV_OP_ALU, rd, f3, rd, rs, f7));
  }
}

void compile_ebpf(struct ebpf_inst *prog, int len) {
  pc_riscv = 0;

  for (int i = 0; i < len; i++) {
    struct ebpf_inst inst = prog[i];
    uint8_t op = inst.opcode;

    // 1. Instantly get the correct RISC-V destination register
    uint8_t rd = (inst.dst_reg <= 10) ? bpf2rv[inst.dst_reg] : RV_REG_ZERO;

    // 2. Determine the source (either a BPF register or our scratch register)
    uint8_t rs = RV_REG_ZERO;
    bool use_imm = false;

    if (BPF_SRC(op) == BPF_X) {
      rs = (inst.src_reg <= 10) ? bpf2rv[inst.src_reg] : RV_REG_ZERO;
    } else if (BPF_SRC(op) == BPF_K) {
      if (inst.imm >= -2048 && inst.imm <= 2047) {
        use_imm = true;
      } else {
        // Large constant: Load it into 't0' and treat as register-source
        emit_load_imm(RV_REG_T0, inst.imm);
        rs = RV_REG_T0;
      }
    }

    // 3. Unified switch for instructions
    switch (BPF_CLASS(op)) {
    case BPF_ALU:
    case BPF_ALU64:
      switch (BPF_OP(op)) {
      case BPF_ADD: emit_alu_generic(rd, rs, inst.imm, use_imm, RV_F3_ADD, RV_F7_ADD); break;
      case BPF_SUB: emit_alu_generic(rd, rs, inst.imm, use_imm, RV_F3_ADD, RV_F7_SUB); break;
      case BPF_AND: emit_alu_generic(rd, rs, inst.imm, use_imm, RV_F3_AND, RV_F7_ADD); break;
      case BPF_OR:  emit_alu_generic(rd, rs, inst.imm, use_imm, RV_F3_OR,  RV_F7_ADD); break;
      case BPF_XOR: emit_alu_generic(rd, rs, inst.imm, use_imm, RV_F3_XOR, RV_F7_ADD); break;

      case BPF_MOV:
        if (use_imm) {
          // R_dest = constant
          emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_ADD, RV_REG_ZERO, inst.imm));
        } else {
          // R_dest = R_src (or R_dest = large constant via t0)
          emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_ADD, rs, 0));
        }
        break;
      }
      break;

    case BPF_JMP:
      if (BPF_OP(op) == BPF_EXIT) {
        emit_rv32(RV_INST_RET);
      }
      break;
    }
  }
}

int run_jit_filter(struct ebpf_inst *prog, int num_instructions) {
  compile_ebpf(prog, num_instructions);
  asm volatile("fence.i");
  int (*filter)() = (int (*)())jit_memory;
  return filter();
}
