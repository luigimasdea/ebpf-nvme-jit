#ifndef JIT_H
#define JIT_H

#include "ebpf.h"

#include <stdint.h>

/**
 * Compiles eBPF instructions into RISC-V machine code.
 * @param prog Pointer to the array of eBPF instructions.
 * @param len Number of instructions in the program.
 */
void compile_ebpf(struct ebpf_inst *prog, int len);

/**
 * Compiles and executes an eBPF program, returning its exit value (R0).
 * @param prog Pointer to the array of eBPF instructions.
 * @param num_instructions Number of instructions in the program.
 * @return The value of register R0 after execution.
 */
int run_jit_filter(struct ebpf_inst *prog, int num_instructions);

#endif // JIT_H
