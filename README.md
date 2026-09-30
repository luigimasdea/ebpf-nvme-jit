# eBPF-to-RISC-V Bare-Metal JIT & Computational Storage Firmware

A high-performance, bare-metal **eBPF Just-In-Time (JIT) compiler** and **Computational Storage Device (CSD)** runtime targeting **64-bit RISC-V (RV64IMA)** architectures. 

The project evaluates hardware-assisted in-storage data processing by implementing an Asymmetric Multiprocessing (AMP) model on the **StarFive JH7110 SoC (VisionFive 2)**. A dedicated hardware core runs without an operating system, emulating next-generation **NVMe Computational Programs (TP4091)** and **Subsystem Local Memory (SLM)** command sets with microsecond-level latency.

---

## Highlights & Results

- **Ultra-Fast JIT Activation**: Two-pass compiler translating eBPF bytecode directly into native RV64IMA machine code with an activation overhead of only **~33.7 µs** (sub-microsecond control-plane response).
- **Zero OS Overhead**: 100% bare-metal firmware execution (no Linux kernel, libc, or scheduling interrupts on the worker core), delivering deterministic execution with **±0.18% jitter**.
- **High Throughput & Bandwidth Savings**:
  - **99.7% PCIe bus reduction** by filtering unstructured records in-storage before data transfer.
  - Up to **6.50x end-to-end speedup** over host CPU storage pipelines when paired with an internal high-speed flash bus.
  - **Pipelined Double Buffering**: Overlaps I/O fetch with JIT compute execution, maximizing storage channel utilization.
- **Standards Compliant**: Implements the concepts of NVMe Base Specification (TP4091 Computational Programs) and SLM memory model using zero-copy shared memory queues.

---

## Architecture Overview

```
                      HOST (Linux CPU 0-2)
  +---------------------------------------------------------+
  |  Host Application / Benchmark / Loader                  |
  |  - Reads NVMe Storage / Prepares eBPF Program           |
  |  - Shared Memory Ring Buffers (/dev/mem mapping)        |
  +---------------------------+-----------------------------+
                              |
                     Physical DRAM (AMP Partition)
  +---------------------------v-----------------------------+
  |  Base: 0x222000000 (16 MB Reserved)                     |
  |  - 0x222000000: Firmware (.text, .rodata, .data, .bss)  |
  |  - 0x222100000: Bare-metal Stack (1 MB)                 |
  |  - 0x222200000: JIT Executable Buffer (2 MB, RWX)       |
  |  - 0x222400000: NVMe Submission & Completion Queues     |
  |  - 0x222500000: SLM Double Buffers (Buffer A & B)       |
  +---------------------------+-----------------------------+
                              |
                 CSD WORKER (Bare-Metal Core 3)
  +---------------------------v-----------------------------+
  |  Boot via OpenSBI HSM -> boot.S -> main()               |
  |  - Polling Submission Queue (SQ)                        |
  |  - JIT Compilation & fence.i Cache Invalidation         |
  |  - Parallel In-Storage Filtering                        |
  |  - Post Result to Completion Queue (CQ)                 |
  +---------------------------------------------------------+
```

### JIT Compiler Characteristics
- **Two-Pass Engine**: Pass 1 calculates binary size and resolves branch target labels; Pass 2 emits machine code directly into the executable buffer followed by an instruction-cache flush (`fence.i`).
- **ALU32 & ALU64 Support**: Implements arithmetic and logical operations, ensuring strict eBPF standard compliance (e.g., zero-extension of 32-bit registers to 64-bit and safe division-by-zero handling).
- **Register Mapping**: Maps eBPF virtual registers (`r0`-`r10`) directly to native RISC-V registers (`a0`-`a5`, `s1`-`s5`) to eliminate register spilling overhead for standard compute kernels.
- **Memory & Branches**: Full support for LDX/STX operations (byte, half-word, word, double-word) and conditional relative jumps.

---

## Repository Structure

```
├── apps/               # Example eBPF applications (analytics_simple, analytics_advanced)
├── firmware/           # Bare-metal CSD runtime
│   ├── arch/           # Low-level bootstrap (boot.S) and memory map (linker.ld)
│   ├── include/        # eBPF, RISC-V ISA, and NVMe queue headers
│   └── src/            # JIT engine (jit.c), queue logic, and firmware main loop
├── host/               # Host-side utilities (host_loader, host_benchmark)
├── tools/              # Benchmarking suite, datasets, and kick_core kernel module
│   ├── kick_core/      # Kernel module triggering OpenSBI HSM to start Hart 4
│   └── *.py            # Automated evaluation and plotting scripts
├── Makefile            # Top-level build orchestration
└── README.md
```

---

## Getting Started

### Prerequisites

- **RISC-V Toolchain**: `riscv64-linux-gnu-gcc` (or native GCC if building directly on the target)
- **Clang/LLVM**: `clang` with BPF backend support and `llvm-objcopy`
- **Linux Kernel Headers**: Required to build the core-kicker module (`tools/kick_core`) on VisionFive 2
- **Python 3**: For running benchmark scripts and generating plots (`matplotlib`, `numpy`)

### Building the Project

From the project root:

```bash
# Build all components (firmware, host tools, eBPF programs, kick_core module)
make all
```

Individual targets:
- `make firmware`: Builds `firmware/build/firmware.bin`
- `make host`: Compiles `host/host_loader` and `host/host_benchmark`
- `make app`: Compiles C analytics programs into standalone eBPF binaries (`apps/*.bin`)
- `make kick`: Compiles `tools/kick_core/vf2_kick.ko` (target platform only)

---

## Running on Hardware (VisionFive 2)

### 1. Memory Isolation Setup
Ensure Linux boots with reserved physical memory for AMP (e.g., via `mem=2500M` in U-Boot kernel parameters) so that physical range `0x222000000 - 0x223000000` (16 MB) is untouched by the kernel.

### 2. Booting the CSD Worker Core
Load the firmware binary into the reserved memory and kick the isolated CPU core via OpenSBI HSM:

```bash
# Load firmware to physical DRAM and boot Hart 4
sudo insmod tools/kick_core/vf2_kick.ko
```

### 3. Loading eBPF Programs & Benchmarking
Use the host-side utilities to interact with the bare-metal worker:

```bash
# Load an eBPF program into the CSD
sudo ./host/host_loader apps/analytics_simple.bin

# Run the end-to-end benchmark
sudo ./host/host_benchmark
```

### 4. Running the Evaluation Suite
Automated scripts in `tools/` reproduce the thesis experimental results:

```bash
# Run micro-benchmarks (JIT load & activation latency)
python3 tools/run_micro_benchmark.py

# Run I/O chunking matrix benchmarks (Host vs CSD Sequential vs CSD Pipelined)
python3 tools/run_matrix_benchmark.py

# Run selectivity sweep (3% to 100%)
python3 tools/run_selectivity_sweep.py
```

---

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
