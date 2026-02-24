#include "ebpf.h"
#include "jit.h"
#include "utils.h"

int main() {
    uart_print("\n[NVMe JIT] Booting firmware...\n");

    // 1. SIMULATE INCOMING eBPF PROGRAM FROM THE HOST
    // Equivalent high-level logic:
    // R0 = 100;
    // R1 = 50;
    // R0 = R0 + R1;
    // return R0;

    struct ebpf_inst test_prog[] = {
        // Instr 0: MOV R0, 10 (Binary: 1010)
        { BPF_ALU | BPF_MOV | BPF_K, 0, 0, 0, 10 },
        
        // Instr 1: MOV R1, 12 (Binary: 1100)
        { BPF_ALU | BPF_MOV | BPF_K, 1, 0, 0, 12 },
        
        // Instr 2: AND R0, R1 (R0 = R0 & R1)
        { BPF_ALU | BPF_AND | BPF_X, 0, 1, 0, 0 },
        
        // Instr 3: EXIT (Returns R0, expecting 8)
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };

    int num_inst = sizeof(test_prog) / sizeof(struct ebpf_inst);

    uart_print("[NVMe JIT] Compiling eBPF bytecode to RISC-V...\n");

    // 2. RUN THE JIT COMPILER
    int result = run_jit_filter(test_prog, num_inst);

    // 3. PRINT THE RESULT
    uart_print("\n>>> JIT EXECUTION RESULT: ");
    uart_print_int(result);
    uart_print(" <<<\n\n");

    // 4. CLEAN SHUTDOWN
    uart_print("[NVMe JIT] Shutting down...\n");
    // Special QEMU trick: writing 0x5555 to this address powers off the VM
    *(volatile uint32_t *)0x100000 = 0x5555; 

    // Fallback infinite loop just in case
    // while (1) {
    //     asm volatile("wfi"); 
    // }
    
    return 0;
}
