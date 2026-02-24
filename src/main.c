#include "ebpf.h"
#include "jit.h"
#include "utils.h"

int main() {
  // 1. SIMULIAMO L'HOST NVMe (es. il PC)
  // Creiamo il programma eBPF che vogliamo inviare al disco.
  // Struttura: {opcode, dst_reg, src_reg, offset, imm}
  struct ebpf_inst programma_ricevuto[] = {
      // Istruzione 1: MOV R0, 12
      // (Usa ALU 32-bit | Operazione MOV | Sorgente Costante)
      {BPF_ALU | BPF_MOV | BPF_K, 0, 0, 0, 12},

      // Istruzione 2: EXIT
      // (Usa JMP | Operazione EXIT)
      {BPF_JMP | BPF_EXIT, 0, 0, 0, 0}
  };

  // Calcoliamo automaticamente quante istruzioni ci sono nell'array
  int num_istruzioni = sizeof(programma_ricevuto) / sizeof(struct ebpf_inst);

  // 2. PASSIAMO IL PROGRAMMA AL JIT
  // Il nostro motore farà tutto il lavoro sporco e ci ridarà il 42
  int risultato = run_jit_filter(programma_ricevuto, num_istruzioni);

  uart_print("Risultato JIT: ");
  uart_print_int(risultato);
  uart_print("\n");

  // Chiudi QEMU automaticamente (Trucco speciale per la macchina 'virt')
  // Scrivere 0x5555 a questo indirizzo spegne la macchina virtuale
  *(volatile uint32_t *)0x100000 = 0x5555;

  // 4. METTIAMO IL CONTROLLER IN PAUSA
  // while (1) {
  //     asm volatile("wfi");
  // }

  return 0;
}
