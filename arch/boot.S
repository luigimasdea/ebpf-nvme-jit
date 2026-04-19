.section .init
.option norvc
.global _start

_start:
    /* 1. Identify Core (Hart) ID */
    /* When started by SBI hart_start, a0 contains the Hart ID */
    li t0, 3
    bne a0, t0, _park_core

    /* 2. Setup Stack Pointer */
    la sp, _stack_top

    /* 3. Setup Global Pointer (gp) */
    /* Used by GCC for small-data relaxation (performance) */
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    /* 4. Disable Interrupts for startup */
    csrw mie, zero

    /* 5. Zero-initialize BSS section */
    la t0, __bss_start
    la t1, __bss_end
    bge t0, t1, _to_main

_zero_loop:
    sd zero, 0(t0)
    addi t0, t0, 8
    blt t0, t1, _zero_loop

_to_main:
    /* 6. Jump to C Main function */
    /* We use 'tail' to avoid returning */
    tail main

_park_core:
    /* If an unexpected core enters here, we put it in wait state */
    wfi
    j _park_core
