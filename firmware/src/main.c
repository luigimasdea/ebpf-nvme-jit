#include "ebpf.h"
#include "jit.h"
#include "utils.h"

/**
 * eBPF Helper Lookup Table
 */
void* bpf_helper_lookup(int32_t imm) {
    switch (imm) {
        case 1: return (void*)uart_print;
        case 2: return (void*)uart_print_int;
        case 3: return (void*)uart_print_hex;
        default: return (void*)0;
    }
}

#ifdef TEST_RUNNER
#include "test_case.h"
#define test_prog_len sizeof(test_prog)
#else
#include "gen/app_data.h"
#define test_prog ((struct ebpf_inst *)app_bin)
#define test_prog_len app_bin_len
#endif

struct filter_context {
    uint64_t count;
    uint64_t threshold;
    uint64_t values[8];
};

int main() {
    uart_print("\n[NVMe JIT] Booting JIT Firmware (Record Filter)...\n");

    // Determine the number of eBPF instructions (8 bytes each)
    int num_inst = test_prog_len / sizeof(struct ebpf_inst);

    uart_print("[NVMe JIT] Compiling Host App to RISC-V...\n");

    // Sample dataset passed as context (R1) to the eBPF program:
    // Testing predicate: values[i] >= 50
    // Dataset: {12, 85, 42, 99, 10, 50, 3, 77} -> 4 values are >= 50 (85, 99, 50, 77)
    struct filter_context ctx = {
        .count = 8,
        .threshold = 50,
        .values = { 12, 85, 42, 99, 10, 50, 3, 77 }
    };

    // Execute JIT compilation and run the resulting machine code
    uint64_t result = run_jit_filter(test_prog, num_inst, &ctx);

    // Display the execution result
    uart_print("\n>>> JIT FILTER MATCHES: ");
    uart_print_uint64(result);
    uart_print(" / 8 records <<<\n\n");

    uart_print("[NVMe JIT] Test completed. Halting Hart via SBI HSM...\n");

    // Request OpenSBI to stop this Hart (SBI HSM HART_STOP: ext=0x48534D, fid=1)
    register unsigned long a7 asm("a7") = 0x48534D;
    register unsigned long a6 asm("a6") = 1;
    asm volatile("ecall" : : "r"(a7), "r"(a6) : "memory");

    // Fallback loop if OpenSBI returns
    while(1) {
        asm volatile("wfi");
    }
    return 0;
}
