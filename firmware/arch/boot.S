.section .init
.option norvc
.global _start

_start:
    /* 1. Setup Stack Pointer */
    la sp, _stack_top

    /* 3. Setup Global Pointer */
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    /* 4. Disable Interrupts (Supervisor mode) */
    /* Commented out for safety since SBI already starts the hart with interrupts disabled */
    // csrw sie, zero

    /* 5. Zero-initialize BSS */
    la t0, __bss_start
    la t1, __bss_end
    bge t0, t1, _to_main

_zero_loop:
    sd zero, 0(t0)
    addi t0, t0, 8
    blt t0, t1, _zero_loop

_to_main:
    /* 6. Jump to C */
    tail main

_park_core:
    wfi
    j _park_core
