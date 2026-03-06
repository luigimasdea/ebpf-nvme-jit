# eBPF JIT Compiler for RISC-V (RV64G)

This project implements a lightweight **Just-In-Time (JIT)** compiler designed to translate eBPF bytecode into native **64-bit RISC-V (RV64G)** instructions. The compiler is built for bare-metal or firmware environments, enabling efficient execution of eBPF programs directly on RISC-V hardware.

## Key Features

*   **Full ALU Support**: Implementation of 64-bit (`ALU64`) and 32-bit (`ALU`) operations.
*   **eBPF Standard Compliance**:
    *   **Zero-Extension**: 32-bit operations correctly zero-extend to 64 bits, adhering to the eBPF specification and avoiding RISC-V's default sign-extension.
    *   **Safe Division**: Division-by-zero handling (returns 0 as per eBPF standard) to prevent hardware exceptions.
    *   **Endianness Instructions**: Support for `BPF_END` (Little Endian and Big Endian conversions) for 16, 32, and 64-bit formats.
*   **Control Flow**: Support for conditional jumps (32/64-bit), helper calls (`CALL`), and `EXIT`.
*   **Memory Operations**: Support for Load/Store instructions (Byte, Half, Word, Double Word).
*   **Atomic Operations**: Experimental support for atomic operations (RISC-V 'A' extension).
*   **100% Bare-Metal**: No dependencies on Linux, libc, or host operating systems. Designed to run directly on silicon (or in pure hardware emulation).

## Prerequisites

To build and run the project, you need:

1.  **RISC-V Toolchain**: `riscv64-linux-gnu-gcc`
2.  **LLVM/Clang**: `clang` (with BPF target support) and `llvm-objcopy`
3.  **QEMU Emulator**: `qemu-system-riscv64`
4.  **Utilities**: `xxd`, `make`, `python3` (for tests)

## Project Structure

*   `src/jit.c`: The core of the JIT compiler (eBPF decoding and RISC-V emission).
*   `src/main.c`: Firmware entry point and manual test logic.
*   `apps/`: Host-side C programs to be compiled into eBPF.
*   `include/ebpf.h`: eBPF opcode and structure definitions.
*   `include/riscv.h`: Macros and constructors for RISC-V machine instructions.
*   `arch/`: Linker script and boot code (`boot.S`) for bare-metal environment.
*   `tests/`: Python test suite for automated JIT validation.

## Compilation

The project uses a `Makefile` to manage firmware compilation.

To compile the project and generate the `firmware.elf` file:
```bash
make
```

To clean compiled files:
```bash
make clean
```

## Execution

You can run the compiled firmware using the QEMU emulator integrated into the `Makefile`:

```bash
make run
```
The firmware will load a sample eBPF program, compile it via the JIT, and display the execution result on the UART console.

## Automated Testing

The project includes a comprehensive test suite that verifies the correctness of every supported instruction (ALU, JMP, Memory, Endianness, etc.).

To run all tests:
```bash
python3 tests/run_tests.py
```

The test suite performs the following operations for each case:
1. Generates a specific eBPF program.
2. Compiles the firmware including that program.
3. Starts QEMU and captures the output.
4. Compares the result returned by register `R0` with the expected value.

## Technical Notes

The JIT operates in two passes:
1.  **Analysis**: Calculates the total size of the generated code and maps eBPF instruction offsets to RISC-V addresses (necessary for resolving jumps).
2.  **Emission**: Generates binary machine code directly into the execution memory.
