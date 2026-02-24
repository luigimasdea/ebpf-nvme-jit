#ifndef JIT_H
#define JIT_H

#include "ebpf.h"

#include <stdint.h>

void emit_rv32(uint32_t istruzione);
void compile_ebpf(struct ebpf_inst *programma, int num_istruzioni);
int run_jit_filter(struct ebpf_inst *prog, int num_istruzioni);

#endif
