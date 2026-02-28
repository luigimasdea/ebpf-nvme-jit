#include "ebpf.h"
#include "jit.h"
#include "utils.h"

#ifdef TEST_RUNNER
#include "test_case.h"
#else
struct ebpf_inst test_prog[] = {
    // Instr 0: R0 = 10
    { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 10 },
    
    // Instr 1: R0 = R0 << 2 (10 << 2 = 40)
    { BPF_ALU64 | BPF_LSH | BPF_K, 0, 0, 0, 2 },
    
    // Instr 2: R0 = R0 % 7 (40 % 7 = 5)
    { BPF_ALU64 | BPF_MOD | BPF_K, 0, 0, 0, 7 },
    
    // Instr 3: EXIT (Returns R0, expecting 5)
    { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
};
#endif

int main() {
    uart_print("\n[NVMe JIT] Booting firmware...\n");

    int num_inst = sizeof(test_prog) / sizeof(struct ebpf_inst);

    uart_print("[NVMe JIT] Compiling eBPF bytecode to RISC-V...\n");

    // RUN THE JIT COMPILER
    int result = run_jit_filter(test_prog, num_inst);

    // PRINT THE RESULT
    uart_print("\n>>> JIT EXECUTION RESULT: ");
    uart_print_int(result);
    uart_print(" <<<\n\n");

    // CLEAN SHUTDOWN
    uart_print("[NVMe JIT] Shutting down...\n");
    *(volatile uint32_t *)0x100000 = 0x5555; 

    return 0;
}
