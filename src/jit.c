#include "jit.h"
#include "ebpf.h"
#include "riscv.h"

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

void compile_ebpf(struct ebpf_inst *prog, int len) {
  pc_riscv = 0;

  for (int i = 0; i < len; i++) {
    struct ebpf_inst inst = prog[i];
    uint8_t op = inst.opcode;

    // 1. Instantly get the correct RISC-V destination register
    // (We ensure we don't read out of bounds of our 11-register array)
    uint8_t rd = (inst.dst_reg <= 10) ? bpf2rv[inst.dst_reg] : RV_REG_ZERO;

    // 2. Determine the source (either a BPF register or our scratch register)
    uint8_t rs = RV_REG_ZERO; // Default

    if (BPF_SRC(op) == BPF_X) {
      // Source is another eBPF register
      rs = (inst.src_reg <= 10) ? bpf2rv[inst.src_reg] : RV_REG_ZERO;
    } else if (BPF_SRC(op) == BPF_K) {
      // Source is a constant number.
      if (inst.imm < -2048 || inst.imm > 2047) {
        // It's huge! Load it into the scratch register 't0' first.
        emit_load_imm(RV_REG_T0, inst.imm);
        rs = RV_REG_T0; // Now, pretend the user asked for a register operation!
      }
    }

    // 3. The Unified Switch
    switch (BPF_CLASS(op)) {

    case BPF_ALU:
    case BPF_ALU64:
    switch (BPF_OP(op)) {
        /* =======================================================
         * 1. PSEUDO / UNARY OPERATIONS (Isolated)
         * ======================================================= */
        case BPF_MOV:
            if (BPF_SRC(op) == BPF_K && inst.imm >= -2048 && inst.imm <= 2047) {
                // ADDI rd, zero, imm
                emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_ADD, RV_REG_ZERO, inst.imm));
            } else {
                // ADDI rd, rs, 0 (This is the RISC-V 'MV' pseudo-instruction)
                emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, RV_F3_ADD, rs, 0));
            }
            break;

        case BPF_NEG: // eBPF NEG: rd = -rd
            // RISC-V doesn't have NEG. We use: SUB rd, zero, rd
            emit_rv32(RV_MAKE_R(RV_OP_ALU, rd, RV_F3_SUB, RV_REG_ZERO, rd, RV_F7_SUB));
            break;

        /* =======================================================
         * 2. GENERIC BINARY OPERATIONS (Grouped and Deduplicated)
         * ======================================================= */
        case BPF_ADD:
        case BPF_SUB:
        case BPF_AND:
        case BPF_OR:
        case BPF_XOR: {
            uint8_t f3 = 0;
            uint8_t f7 = RV_F7_DEF;

            // Map the specific hardware codes
            if (BPF_OP(op) == BPF_ADD) { f3 = RV_F3_ADD; }
            if (BPF_OP(op) == BPF_SUB) { f3 = RV_F3_SUB; f7 = RV_F7_SUB; }
            if (BPF_OP(op) == BPF_AND) { f3 = RV_F3_AND; }
            if (BPF_OP(op) == BPF_OR)  { f3 = RV_F3_OR; }
            if (BPF_OP(op) == BPF_XOR) { f3 = RV_F3_XOR; }

            // The single generation logic for all binary math
            if (BPF_SRC(op) == BPF_K && BPF_OP(op) != BPF_SUB && inst.imm >= -2048 && inst.imm <= 2047) {
                emit_rv32(RV_MAKE_I(RV_OP_IMM, rd, f3, rd, inst.imm));
            } else {
                emit_rv32(RV_MAKE_R(RV_OP_ALU, rd, f3, rd, rs, f7));
            }
            break;
        }
        
        default:
            // Unhandled ALU operation
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

int run_jit_filter(struct ebpf_inst *prog, int num_istruzioni) {

  // 1. Compiliamo dinamicamente il program ricevuto dal main
  compile_ebpf(prog, num_istruzioni);

  // 2. Sincronizziamo la cache prima di eseguire
  asm volatile("fence.i");

  // 3. Eseguiamo il codice RISC-V appena generato
  int (*filtro)() = (int (*)())jit_memory;
  return filtro();
}
