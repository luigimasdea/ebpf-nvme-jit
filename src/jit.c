#include "jit.h"
#include "ebpf.h"
#include "riscv.h"
#include "utils.h"

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

void emit_alu(struct ebpf_inst inst, uint8_t rd, uint8_t rs, uint8_t f3, uint8_t f7) {
    uint8_t op = inst.opcode;
    bool is_alu64 = (BPF_CLASS(op) == BPF_ALU64);
    bool use_imm = false;

    // 1. Resolve Immediate vs Register (And handle massive immediates here!)
    if (BPF_SRC(op) == BPF_K) {
        bool is_shift = (f3 == RV_F3_SLL || f3 == RV_F3_SRL);
        int32_t max_shift = is_alu64 ? 63 : 31;
        
        if (is_shift && inst.imm >= 0 && inst.imm <= max_shift) {
            use_imm = true;
        } else if (!is_shift && inst.imm >= -2048 && inst.imm <= 2047) {
            use_imm = true;
        } else {
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
        // Path D: Shifts pack the funct7 flag at bits [11:5] of the immediate field.
        uint32_t shift_amt = (uint32_t)inst.imm & (is_alu64 ? 0x3F : 0x1F);
        uint32_t packed_imm = (f7 << 5) | shift_amt; 
        emit_rv32(RV_MAKE_I(op_imm, rd, f3, rd, packed_imm));
    } 
    else {
        // Path E: Standard, clean Immediate Math (ADD, AND, OR, XOR)
        emit_rv32(RV_MAKE_I(op_imm, rd, f3, rd, inst.imm & 0xFFF));
    }
}

/* =========================================================================
 * MAIN COMPILER LOOP
 * ========================================================================= */
void compile_ebpf(struct ebpf_inst *prog, int len) {
    pc_riscv = 0;

    for (int i = 0; i < len; i++) {
        struct ebpf_inst inst = prog[i];
        uint8_t op = inst.opcode;

        // Map base registers safely
        uint8_t rd = (inst.dst_reg <= 10) ? bpf2rv[inst.dst_reg] : RV_REG_ZERO;
        uint8_t rs = (inst.src_reg <= 10) ? bpf2rv[inst.src_reg] : RV_REG_ZERO;
        bool is_alu64 = (BPF_CLASS(op) == BPF_ALU64);

        switch (BPF_CLASS(op)) {
            case BPF_ALU:
            case BPF_ALU64:
                switch (BPF_OP(op)) {
                    // --- GENERIC MATH (Handled flawlessly by emit_alu) ---
                    case BPF_ADD:  emit_alu(inst, rd, rs, RV_F3_ADD, RV_F7_ADD); break;
                    case BPF_SUB:  emit_alu(inst, rd, rs, RV_F3_ADD, RV_F7_SUB); break;
                    case BPF_AND:  emit_alu(inst, rd, rs, RV_F3_AND, RV_F7_ADD); break;
                    case BPF_OR:   emit_alu(inst, rd, rs, RV_F3_OR,  RV_F7_ADD); break;
                    case BPF_XOR:  emit_alu(inst, rd, rs, RV_F3_XOR, RV_F7_ADD); break;
                    case BPF_MUL:  emit_alu(inst, rd, rs, RV_F3_MUL, RV_F7_MUL); break;
                    case BPF_DIV:  emit_alu(inst, rd, rs, RV_F3_DIV, RV_F7_MUL); break;
                    case BPF_MOD:  emit_alu(inst, rd, rs, RV_F3_REM, RV_F7_MUL); break;
                    case BPF_LSH:  emit_alu(inst, rd, rs, RV_F3_SLL, RV_F7_ADD); break;
                    case BPF_RSH:  emit_alu(inst, rd, rs, RV_F3_SRL, RV_F7_ADD); break;
                    case BPF_ARSH: emit_alu(inst, rd, rs, RV_F3_SRL, RV_F7_SRA); break;

                    // --- PSEUDO INSTRUCTIONS (Isolated) ---
                    case BPF_MOV:
                        if (BPF_SRC(op) == BPF_K) {
                            if (inst.imm >= -2048 && inst.imm <= 2047) {
                                emit_rv32(RV_MAKE_I(is_alu64 ? RV_OP_IMM : RV_OP_IMM_32, rd, RV_F3_ADD, RV_REG_ZERO, inst.imm));
                            } else {
                                emit_load_imm(RV_REG_T0, inst.imm);
                                emit_rv32(RV_MAKE_I(is_alu64 ? RV_OP_IMM : RV_OP_IMM_32, rd, RV_F3_ADD, RV_REG_T0, 0));
                            }
                        } else {
                            emit_rv32(RV_MAKE_I(is_alu64 ? RV_OP_IMM : RV_OP_IMM_32, rd, RV_F3_ADD, rs, 0));
                        }
                        break;

                    case BPF_NEG:
                        emit_rv32(RV_MAKE_R(is_alu64 ? RV_OP_ALU : RV_OP_ALU_32, rd, RV_F3_ADD, RV_REG_ZERO, rd, RV_F7_SUB));
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
