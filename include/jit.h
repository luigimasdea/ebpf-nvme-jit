#ifndef JIT_H
#define JIT_H

#include "ebpf.h"

#include <stdint.h>

void emit_rv32(uint32_t inst);
void emit_load_imm(uint8_t rd, int32_t imm);
void compile_ebpf(struct ebpf_inst *prog, int len);
int run_jit_filter(struct ebpf_inst *prog, int num_istruzioni);

#endif
