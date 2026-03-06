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

#include "gen/app_data.h"
#define test_prog ((struct ebpf_inst *)app_bin)
#define test_prog_len app_bin_len

int main() {
    uart_print("\n[NVMe JIT] Booting JIT Firmware...\n");

    // Determine the number of eBPF instructions (8 bytes each)
    int num_inst = test_prog_len / sizeof(struct ebpf_inst);

    uart_print("[NVMe JIT] Compiling Host App to RISC-V...\n");

    // Sample data structure passed as context (R1) to the eBPF program
    uint64_t ctx_data = 100;
    
    // Execute JIT compilation and run the resulting machine code
    uint64_t result = run_jit_filter(test_prog, num_inst, &ctx_data);

    // Display the execution result
    uart_print("\n>>> JIT EXECUTION RESULT: ");
    uart_print_uint64(result);
    uart_print(" <<<\n\n");

    // Shutdown the emulated system (Exit QEMU)
    uart_print("[NVMe JIT] Shutting down...\n");
    *(volatile uint32_t *)0x100000 = 0x5555; 

    return 0;
}
