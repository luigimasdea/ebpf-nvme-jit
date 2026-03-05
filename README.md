# Compilatore JIT eBPF per RISC-V

Questo progetto implementa un compilatore **Just-In-Time (JIT)** leggero progettato per tradurre il bytecode eBPF in istruzioni native **RISC-V 64-bit**. Il compilatore è concepito per girare in ambienti bare-metal o firmware, permettendo l'esecuzione efficiente di filtri o programmi eBPF direttamente sull'hardware RISC-V.

## Caratteristiche Principali

*   **Supporto ALU completo**: Implementazione di operazioni a 64-bit (`ALU64`) e 32-bit (`ALU`).
*   **Conformità Standard eBPF**:
    *   **Zero-Extension**: Le operazioni a 32-bit eseguono correttamente l'azzeramento dei 32 bit superiori, evitando i problemi di estensione del segno nativi di RISC-V.
    *   **Divisione Sicura**: Gestione della divisione per zero secondo lo standard eBPF (restituisce 0 invece di causare eccezioni o risultati indefiniti).
    *   **Istruzioni Endianness**: Supporto completo per `BPF_END` (conversione Little Endian e Big Endian) per formati a 16, 32 e 64 bit.
*   **Salti e Controllo Flusso**: Supporto per salti condizionali a 64 e 32 bit, chiamate a helper (`CALL`) ed `EXIT`.
*   **Operazioni di Memoria**: Supporto per Load/Store di vari formati (Byte, Half, Word, Double Word).
*   **Operazioni Atomiche**: Supporto sperimentale per istruzioni atomiche (estensione 'A' di RISC-V).
*   **100% Bare-Metal**: Nessuna dipendenza da Linux, libc o sistemi operativi host. Progettato per girare direttamente sul silicio (o in emulazione hardware pura).

## Prerequisiti

Per compilare ed eseguire il progetto, sono necessari i seguenti strumenti:

1.  **Toolchain RISC-V**: `riscv64-linux-gnu-gcc`
2.  **Emulatore QEMU**: `qemu-system-riscv64`
3.  **Python 3**: Necessario per l'esecuzione della suite di test automatizzata.

## Struttura del Progetto

*   `src/jit.c`: Il cuore del compilatore JIT (decodifica eBPF ed emissione RISC-V).
*   `src/main.c`: Entry point del firmware e logica di test manuale.
*   `include/ebpf.h`: Definizioni degli opcode e delle strutture eBPF.
*   `include/riscv.h`: Macro e costruttori per le istruzioni macchina RISC-V.
*   `arch/`: Script di linker e codice di avvio (`boot.S`) per ambiente bare-metal.
*   `tests/`: Suite di test in Python per la validazione automatica del JIT.

## Compilazione

Il progetto utilizza un `Makefile` per gestire la compilazione del firmware.

Per compilare il progetto e generare il file `firmware.elf`:
```bash
make
```

Per pulire i file compilati:
```bash
make clean
```

## Esecuzione

È possibile eseguire il firmware compilato utilizzando l'emulatore QEMU integrato nel `Makefile`:

```bash
make run
```
Il firmware caricherà un programma eBPF d'esempio, lo compilerà tramite il JIT e visualizzerà il risultato dell'esecuzione sulla console UART.

## Test Automatizzati

Il progetto include una suite di test completa che verifica la correttezza di ogni istruzione supportata (ALU, JMP, Memoria, Endianness, ecc.).

Per eseguire tutti i test:
```bash
python3 tests/run_tests.py
```

La suite di test esegue le seguenti operazioni per ogni caso:
1. Genera un programma eBPF specifico.
2. Compila il firmware includendo quel programma.
3. Avvia QEMU e cattura l'output.
4. Confronta il risultato restituito dal registro `R0` con il valore atteso.

## Note Tecniche

Il JIT opera in due passaggi:
1.  **Analisi**: Calcola la dimensione totale del codice generato e mappa gli offset delle istruzioni eBPF sugli indirizzi RISC-V (necessario per risolvere i salti).
2.  **Emissione**: Genera il codice macchina binario direttamente nella memoria di esecuzione.
