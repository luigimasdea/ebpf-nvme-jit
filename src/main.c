#include "jit.h"
#include "ebpf.h"

int main() {
    // 1. SIMULIAMO L'HOST NVMe (es. il PC)
    // Creiamo il programma eBPF che vogliamo inviare al disco.
    // Struttura: {opcode, dst_reg, src_reg, offset, imm}
    struct ebpf_inst programma_ricevuto[] = {
        // Istruzione 1: MOV R0, 42 
        // (Usa ALU 32-bit | Operazione MOV | Sorgente Costante)
        { BPF_ALU | BPF_MOV | BPF_K, 0, 0, 0, 123 }, 
        
        // Istruzione 2: EXIT
        // (Usa JMP | Operazione EXIT)
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };

    // Calcoliamo automaticamente quante istruzioni ci sono nell'array
    int num_istruzioni = sizeof(programma_ricevuto) / sizeof(struct ebpf_inst);

    // 2. PASSIAMO IL PROGRAMMA AL JIT
    // Il nostro motore farà tutto il lavoro sporco e ci ridarà il 42
    int risultato = run_jit_filter(programma_ricevuto, num_istruzioni);

    // 3. SCRIVIAMO IL RISULTATO IN MEMORIA (Per GDB)
    volatile int *memoria_di_debug = (volatile int *)0x80001000;
    *memoria_di_debug = risultato;

    // 4. METTIAMO IL CONTROLLER IN PAUSA
    while (1) {
        asm volatile("wfi"); 
    }
    
    return 0;
}
