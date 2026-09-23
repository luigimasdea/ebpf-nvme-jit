#include "ebpf.h"
#include "jit.h"
#include "utils.h"
#include "nvme_spec.h"
#include "nvme_queue.h"

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

static void stop_hart(void) {
    uart_print("[NVMe JIT] Halting Hart via SBI HSM...\n");
    register unsigned long a7 asm("a7") = 0x48534D;
    register unsigned long a6 asm("a6") = 1;
    asm volatile("ecall" : : "r"(a7), "r"(a6) : "memory");

    while (1) {
        asm volatile("wfi");
    }
}

int main() {
    uart_print("\n========================================\n");
    uart_print("[NVMe JIT] Generic CSD Firmware Booted\n");
    uart_print("[NVMe JIT] Waiting for Host TP4091 commands...\n");
    uart_print("========================================\n\n");

    // Initialize NVMe Submission & Completion Queues in Shared RAM
    nvme_queue_init();

    struct ebpf_inst *loaded_prog = (void *)0;
    uint32_t loaded_len = 0;
    int is_activated = 0;

    // Main NVMe Event / Polling Loop
    while (1) {
        struct nvme_sqe sqe;

        if (!nvme_poll_sq(&sqe)) {
            // No command yet; wait briefly or yield
            continue;
        }

        int silent = (sqe.flags & NVME_FLAG_SILENT);

        if (!silent) {
            uart_print("[NVMe JIT] Received SQE cid=");
            uart_print_int(sqe.cid);
            uart_print(", opcode=0x");
            uart_print_hex(sqe.opcode);
            uart_print("\n");
        }

        switch (sqe.opcode) {
            case NVME_CMD_EBPF_LOAD: {
                if (sqe.prp1 == 0 || sqe.cdw10 == 0 || sqe.cdw10 > MAX_BPF_PROG_LEN) {
                    if (!silent) uart_print("[NVMe JIT] LOAD error: invalid prp1 or instruction count!\n");
                    nvme_post_cqe(sqe.cid, 0, 0, 1);
                    break;
                }

                loaded_prog = (struct ebpf_inst *)sqe.prp1;
                loaded_len = sqe.cdw10; // Number of eBPF instructions
                is_activated = 0;

                if (!silent) {
                    uart_print("[NVMe JIT] LOAD: prog at 0x");
                    uart_print_uint64((uint64_t)loaded_prog);
                    uart_print(", count=");
                    uart_print_int(loaded_len);
                    uart_print(" insns\n");
                }

                nvme_post_cqe(sqe.cid, 0, 0, 0); // Status 0 = Success
                break;
            }

            case NVME_CMD_EBPF_ACTIVATE: {
                if (!loaded_prog || loaded_len == 0) {
                    if (!silent) uart_print("[NVMe JIT] ACTIVATE failed: No program loaded!\n");
                    nvme_post_cqe(sqe.cid, 0, 0, 1); // Status 1 = Error
                    break;
                }

                if (!silent) uart_print("[NVMe JIT] ACTIVATE: Compiling eBPF bytecode to RISC-V...\n");

                uint64_t start_cycles, end_cycles;
                asm volatile("rdcycle %0" : "=r"(start_cycles));

                compile_ebpf(loaded_prog, loaded_len);

                // Flush data cache and invalidate instruction cache for newly compiled code
                asm volatile("fence rw, rw");
                asm volatile("fence.i");

                asm volatile("rdcycle %0" : "=r"(end_cycles));
                uint32_t jit_cycles = (uint32_t)(end_cycles - start_cycles);

                is_activated = 1;
                if (!silent) uart_print("[NVMe JIT] ACTIVATE: Compilation complete!\n");
                nvme_post_cqe(sqe.cid, 0, jit_cycles, 0); // rsvd1 carries JIT compilation cycles
                break;
            }

            case NVME_CMD_EBPF_EXECUTE: {
                if (!is_activated) {
                    if (!silent) uart_print("[NVMe JIT] EXECUTE failed: Program not activated!\n");
                    nvme_post_cqe(sqe.cid, 0, 0, 2); // Status 2 = Not Activated
                    break;
                }

                void *ctx = (void *)sqe.prp1;
                if (!silent) {
                    uart_print("[NVMe JIT] EXECUTE: Running with ctx at 0x");
                    uart_print_uint64((uint64_t)ctx);
                    uart_print("...\n");
                }

                uint64_t (*bpf_fn)(void *ctx) = (uint64_t (*)(void *))0x222200000ULL;

                uint64_t start_cycles, end_cycles;
                asm volatile("rdcycle %0" : "=r"(start_cycles));

                uint64_t result = bpf_fn(ctx);

                asm volatile("rdcycle %0" : "=r"(end_cycles));
                uint32_t exec_cycles = (uint32_t)(end_cycles - start_cycles);

                if (!silent) {
                    uart_print("[NVMe JIT] EXECUTE: Completed! Return value: ");
                    uart_print_uint64(result);
                    uart_print("\n");
                }

                nvme_post_cqe(sqe.cid, (uint32_t)result, exec_cycles, 0); // rsvd1 carries execution cycles
                break;
            }

            case NVME_CMD_EBPF_UNLOAD: {
                if (!silent) uart_print("[NVMe JIT] UNLOAD: Program unloaded.\n");
                loaded_prog = (void *)0;
                loaded_len = 0;
                is_activated = 0;
                nvme_post_cqe(sqe.cid, 0, 0, 0);
                break;
            }

            case NVME_CMD_SHUTDOWN: {
                if (!silent) uart_print("[NVMe JIT] SHUTDOWN: Acking and parking Core 3...\n");
                nvme_post_cqe(sqe.cid, 0, 0, 0);
                stop_hart();
                return 0;
            }

            default: {
                if (!silent) uart_print("[NVMe JIT] Unknown opcode! Rejecting.\n");
                nvme_post_cqe(sqe.cid, 0, 0, 0xFFFF);
                break;
            }
        }
    }

    return 0;
}
