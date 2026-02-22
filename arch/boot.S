.section .init
.global _start

_start:
    # Imposta lo Stack Pointer (sp).
    # QEMU virt machine mappa la RAM partendo da 0x80000000.
    # Mettiamo lo stack molto in alto.
    li sp, 0x80200000
    
    # Salta alla tua funzione main in C
    call main

    # Se il main finisce (non dovrebbe in un firmware), fermati qui all'infinito
hang:
    j hang
