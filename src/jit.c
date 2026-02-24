#include "jit.h"
#include "ebpf.h"
#include "riscv.h"

uint32_t jit_memory[1024] __attribute__((aligned(4)));
int pc_riscv = 0; 

void emit_rv32(uint32_t istruzione) {
    jit_memory[pc_riscv] = istruzione;
    pc_riscv++;
}

void compile_ebpf(struct ebpf_inst *programma, int num_istruzioni) {
    pc_riscv = 0;

    for (int i = 0; i < num_istruzioni; i++) {
        struct ebpf_inst inst = programma[i];
        uint8_t op = inst.opcode;
        
        // Mappatura elementare dei registri (per ora solo R0 -> a0)
        uint32_t rd = (inst.dst_reg == 0) ? RV_REG_A0 : RV_REG_ZERO; 

        // LO SWITCH PRINCIPALE SULLE CLASSI EBPF
        switch (BPF_CLASS(op)) {
            
            case BPF_ALU:
            case BPF_ALU64:
                // Sotto-switch sull'operazione specifica
                switch (BPF_OP(op)) {
                    case BPF_MOV:
                        if (BPF_SRC(op) == BPF_K) {
                            // MOV rd, imm -> in RISC-V diventa: ADDI rd, zero, imm
                            uint32_t rv_inst = RV_MAKE_I(RV_OP_IMM, rd, RV_F3_ADD, RV_REG_ZERO, inst.imm);
                            emit_rv32(rv_inst);
                        }
                        break;
                    
                    // Qui in futuro metteremo case BPF_ADD, case BPF_SUB, ecc.
                }
                break;

            case BPF_JMP:
                switch (BPF_OP(op)) {
                    case BPF_EXIT:
                        // EXIT -> in RISC-V diventa: RET
                        emit_rv32(RV_INST_RET);
                        break;
                }
                break;

            default:
                // Istruzione non supportata dal nostro JIT (per ora la ignoriamo)
                break;
        }
    }
}

int run_jit_filter(struct ebpf_inst *prog, int num_istruzioni) {
    
    // 1. Compiliamo dinamicamente il programma ricevuto dal main
    compile_ebpf(prog, num_istruzioni);

    // 2. Sincronizziamo la cache prima di eseguire
    asm volatile("fence.i");

    // 3. Eseguiamo il codice RISC-V appena generato
    int (*filtro)() = (int (*)()) jit_memory;
    return filtro();
}
