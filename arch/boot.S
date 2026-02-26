.section .init
.global _start

_start:
    # Set the Stack Pointer (sp).
    # QEMU virt machine maps RAM starting from 0x80000000.
    # Place the stack high in memory.
    li sp, 0x80200000
    
    # Jump to the C main function.
    call main

    # If main returns (which should not happen in firmware), loop here indefinitely.
hang:
    j hang
