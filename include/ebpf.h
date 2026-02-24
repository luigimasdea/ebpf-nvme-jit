#ifndef EBPF_H
#define EBPF_H

#include <stdint.h>

/* =========================================================================
 * STRUTTURA ISTRUZIONE eBPF
 * ========================================================================= */
// Ogni istruzione eBPF è grande esattamente 64 bit (8 byte)
struct ebpf_inst {
    uint8_t  opcode;    // Byte 0: L'operazione da eseguire
    uint8_t  dst_reg:4; // Byte 1 (nibble basso): Registro destinazione
    uint8_t  src_reg:4; // Byte 1 (nibble alto): Registro sorgente
    int16_t  offset;    // Byte 2-3: Offset per i salti (es. +5 istruzioni)
    int32_t  imm;       // Byte 4-7: Valore immediato (es. il nostro 42)
};

/* =========================================================================
 * DECODIFICA OPCODE (8 bit)
 * L'opcode eBPF è formato da: [4 bit: Operazione] [1 bit: Sorgente] [3 bit: Classe]
 * ========================================================================= */

// 1. ESTRAZIONE DELLE CLASSI (I 3 bit più bassi: mask 0x07)
#define BPF_CLASS(code) ((code) & 0x07)

#define BPF_LD    0x00  // Load (usato per l'istruzione speciale a 64-bit)
#define BPF_LDX   0x01  // Load da memoria a registro
#define BPF_ST    0x02  // Store immediato in memoria
#define BPF_STX   0x03  // Store da registro a memoria
#define BPF_ALU   0x04  // Matematica a 32-bit (es. int)
#define BPF_JMP   0x05  // Salti a 64-bit (if/else) e uscita
#define BPF_JMP32 0x06  // Salti a 32-bit
#define BPF_ALU64 0x07  // Matematica a 64-bit (es. long)

// 2. ESTRAZIONE DELLA SORGENTE (Il 4° bit: mask 0x08)
#define BPF_SRC(code)   ((code) & 0x08)

#define BPF_K     0x00  // La sorgente è il campo "imm" (costante)
#define BPF_X     0x08  // La sorgente è il "src_reg" (registro)

// 3. ESTRAZIONE DELL'OPERAZIONE (I 4 bit più alti: mask 0xf0)
#define BPF_OP(code)    ((code) & 0xf0)

// Operazioni Matematiche (ALU / ALU64)
#define BPF_ADD   0x00  // Somma (+)
#define BPF_SUB   0x10  // Sottrazione (-)
#define BPF_MUL   0x20  // Moltiplicazione (*)
#define BPF_DIV   0x30  // Divisione (/)
#define BPF_OR    0x40  // OR Operator (||)
#define BPF_AND   0x50  // AND Operator (&&)
#define BPF_MOV   0xb0  // Muovi valore/registro

// Operazioni di Salto (JMP)
#define BPF_JA    0x00  // Salto incondizionato (Jump Always)
#define BPF_JEQ   0x10  // Salta se uguale (==)
#define BPF_JGT   0x20  // Salta se maggiore (>)
#define BPF_EXIT  0x90  // Termina il programma e ritorna R0 

/* =========================================================================
 * ISTRUZIONI SPECIALI
 * ========================================================================= */
// Questa è l'eccezione alla regola: l'istruzione lunga 16 byte
// Corrisponde a (BPF_LD | BPF_DW | BPF_IMM)
#define BPF_LD_IMM64 0x18 

#endif // EBPF_H
