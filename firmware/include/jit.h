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
 * @param ctx Context pointer passed as the first argument (R1).
 * @return The value of register R0 after execution.
 */
uint64_t run_jit_filter(struct ebpf_inst *prog, int num_instructions, void *ctx);

/**
 * Configure executable buffer pointer (useful for test harnesses outside of fixed physical addresses).
 */
void jit_set_memory_target(uint32_t *target);

/**
 * Returns the number of eBPF stack slots currently cached in RISC-V hardware registers.
 */
int jit_get_cached_slots_count(void);

/**
 * Returns the number of RISC-V 32-bit instructions emitted in the last JIT compilation.
 */
int jit_get_emitted_insn_count(void);

#endif // JIT_H
