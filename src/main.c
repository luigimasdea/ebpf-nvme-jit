#include "ebpf.h"
#include "jit.h"
#include "utils.h"

// eBPF Helper Lookup Table
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
#else
struct ebpf_inst test_prog[] = {
    // Context (R1) points to a memory location.
    // Let's load a 64-bit value from R1 (ctx) into R0.
    // R0 = *(u64 *)R1
    { BPF_LDX | BPF_DW | BPF_MEM, 0, 1, 0, 0 },
    
    // R0 = R0 + 5
    { BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 5 },
    
    // EXIT (Returns R0)
    { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
};
#endif

int main() {
    uart_print("\n[NVMe JIT] Booting firmware...\n");

    int num_inst = sizeof(test_prog) / sizeof(struct ebpf_inst);

    uart_print("[NVMe JIT] Compiling eBPF bytecode to RISC-V...\n");

    // DATA FOR CONTEXT
    uint64_t ctx_data = 100;
    
    // RUN THE JIT COMPILER
    uint64_t result = (uint64_t)(uintptr_t)run_jit_filter(test_prog, num_inst, &ctx_data);

    // PRINT THE RESULT
    uart_print("\n>>> JIT EXECUTION RESULT: ");
    uart_print_uint64(result);
    uart_print(" <<<\n\n");

    // CLEAN SHUTDOWN
    uart_print("[NVMe JIT] Shutting down...\n");
    *(volatile uint32_t *)0x100000 = 0x5555; 

    return 0;
}
