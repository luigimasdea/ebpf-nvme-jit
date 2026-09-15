#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "nvme_spec.h"
#include "nvme_queue.h"

#define PHYS_BASE           0x222000000ULL
#define MAP_SIZE            0x01000000ULL  // 16MB
#define FW_BINARY           "firmware/build/firmware.bin"

// Offsets within the 16MB mapped window
#define VCON_OFFSET         0x00400000ULL  // 0x222400000 (Virtual Console)
#define VCON_SIZE           4096

#define NVME_QUEUE_OFFSET   0x00401000ULL  // 0x222401000 (NVMe Queues)
#define SLM_OFFSET          0x00500000ULL  // 0x222500000 (Subsystem Local Memory / Payload)

struct record {
    uint32_t id;
    uint32_t type;       // 1 = SALE, 2 = REFUND, 3 = EXPENSE
    uint32_t amount;     // Transaction amount
    uint32_t timestamp;  // Unix timestamp
};

struct analytics_context {
    // --- Query Predicates (Inputs) ---
    uint32_t record_count;
    uint32_t target_type;
    uint32_t min_amount;
    uint32_t max_amount;

    // --- Aggregations (Outputs written back by eBPF) ---
    uint32_t matches;
    uint32_t sum_amount;
    uint32_t max_matched_amount;
    uint32_t min_matched_amount;

    // --- Dataset in SLM ---
    struct record records[16];
};

static volatile uint32_t *vcon_idx;
static volatile char *vcon_buf;
static uint32_t last_vcon_read = 0;

static void drain_vcon(void) {
    uint32_t current_idx = *vcon_idx;
    while (last_vcon_read < current_idx) {
        char c = vcon_buf[last_vcon_read % (VCON_SIZE - 8)];
        if (c != '\0') {
            putchar(c);
            fflush(stdout);
        }
        last_vcon_read++;
    }
}

static int submit_nvme_cmd(volatile struct nvme_queue_mem *qmem,
                           struct nvme_sqe *cmd,
                           struct nvme_cqe *out_cqe,
                           int timeout_ms) {
    uint32_t tail = qmem->regs.sq_tail;
    uint32_t head = qmem->regs.sq_head;

    // Check if Submission Queue is full
    if ((tail - head) >= NVME_QUEUE_DEPTH) {
        printf("[HOST ERROR] Submission Queue full!\n");
        return -1;
    }

    // Write command into SQ ring buffer
    uint32_t sq_idx = tail % NVME_QUEUE_DEPTH;
    qmem->sq[sq_idx] = *cmd;

    // Memory barrier before ringing Doorbell
    __sync_synchronize();

    // Ring SQ Tail Doorbell
    qmem->regs.sq_tail = tail + 1;
    __sync_synchronize();

    // Poll Completion Queue for response matching cmd->cid
    int elapsed = 0;
    while (elapsed < timeout_ms) {
        drain_vcon();

        if (qmem->regs.cq_tail != qmem->regs.cq_head) {
            uint32_t cq_idx = qmem->regs.cq_head % NVME_QUEUE_DEPTH;
            struct nvme_cqe cqe = qmem->cq[cq_idx];

            if (cqe.cid == cmd->cid) {
                *out_cqe = cqe;

                // Advance Host CQ Head Doorbell
                qmem->regs.cq_head++;
                __sync_synchronize();
                return 0; // Success
            }
        }

        usleep(2000); // 2ms sleep
        elapsed += 2;
    }

    printf("[HOST ERROR] Command cid=%d timed out after %d ms!\n", cmd->cid, timeout_ms);
    return -2;
}

int main() {
    int mem_fd, fw_fd;
    uint8_t *map_base;

    printf("====================================================\n");
    printf("[HOST] VisionFive 2 NVMe Computational Storage Host\n");
    printf("====================================================\n");

    mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd < 0) {
        perror("open /dev/mem");
        return 1;
    }

    map_base = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, PHYS_BASE);
    if (map_base == MAP_FAILED) {
        perror("mmap");
        close(mem_fd);
        return 1;
    }

    // Set up mapped pointers
    vcon_idx = (volatile uint32_t *)(map_base + VCON_OFFSET + VCON_SIZE - 4);
    vcon_buf = (volatile char *)(map_base + VCON_OFFSET);
    volatile struct nvme_queue_mem *qmem = (volatile struct nvme_queue_mem *)(map_base + NVME_QUEUE_OFFSET);
    struct analytics_context *slm_ctx = (struct analytics_context *)(map_base + SLM_OFFSET);

    // 1. Reset Virtual Console and NVMe Queues
    printf("[HOST] Resetting VCON and NVMe queues in RAM...\n");
    *vcon_idx = 0;
    memset((void*)vcon_buf, 0, VCON_SIZE - 4);
    memset((void*)qmem, 0, sizeof(struct nvme_queue_mem));

    // 2. Inject firmware binary
    printf("[HOST] Injecting firmware into RAM (0x222000000)...\n");
    fw_fd = open(FW_BINARY, O_RDONLY);
    if (fw_fd < 0) {
        fw_fd = open("../" FW_BINARY, O_RDONLY);
    }

    if (fw_fd >= 0) {
        ssize_t bytes_read = read(fw_fd, map_base, 0x100000);
        close(fw_fd);
        printf("[HOST] Firmware injected (%zd bytes).\n", bytes_read);
    } else {
        printf("[HOST WARNING] Could not open firmware binary! Skipping injection.\n");
    }

    printf("\n[HOST] Waiting for Core 3 boot... (insmod vf2_kick.ko if not already running)\n");
    printf("--- [CORE 3 CONSOLE] ---\n");

    // Wait until Core 3 initializes queues and marks status as READY
    while (qmem->regs.status != NVME_STATUS_READY) {
        drain_vcon();
        usleep(5000);
    }
    drain_vcon();
    printf("--- [CORE 3 READY] ---\n\n");

    // 3. Prepare dataset in SLM (Subsystem Local Memory at 0x222500000)
    printf("[HOST] Preparing dataset & query parameters in SLM (0x222500000)...\n");
    memset(slm_ctx, 0, sizeof(struct analytics_context));
    slm_ctx->record_count = 10;
    slm_ctx->target_type = 1;      // Filter: Type == SALE (1)
    slm_ctx->min_amount = 50;       // Filter: Amount >= 50
    slm_ctx->max_amount = 500;      // Filter: Amount <= 500

    struct record sample_data[10] = {
        { .id = 1,  .type = 1, .amount = 120, .timestamp = 1000 }, // MATCH
        { .id = 2,  .type = 2, .amount = 80,  .timestamp = 1001 }, // Wrong type (2)
        { .id = 3,  .type = 1, .amount = 40,  .timestamp = 1002 }, // Too low (< 50)
        { .id = 4,  .type = 1, .amount = 450, .timestamp = 1003 }, // MATCH
        { .id = 5,  .type = 3, .amount = 300, .timestamp = 1004 }, // Wrong type (3)
        { .id = 6,  .type = 1, .amount = 600, .timestamp = 1005 }, // Too high (> 500)
        { .id = 7,  .type = 1, .amount = 200, .timestamp = 1006 }, // MATCH
        { .id = 8,  .type = 1, .amount = 50,  .timestamp = 1007 }, // MATCH
        { .id = 9,  .type = 2, .amount = 500, .timestamp = 1008 }, // Wrong type (2)
        { .id = 10, .type = 1, .amount = 350, .timestamp = 1009 }  // MATCH
    };
    memcpy(slm_ctx->records, sample_data, sizeof(sample_data));

    printf("  [Query] Filter: Type == 1 (SALE), Amount in [50, 500], Total Records: 10\n");
    printf("  [Expected] Matches: 5, Sum: $1170, Min: $50, Max: $450\n");

    struct nvme_sqe sqe;
    struct nvme_cqe cqe;

    // 4. Send TP4091 Command 1: LOAD
    printf("\n[HOST -> DEV] Submitting NVME_CMD_EBPF_LOAD (cid=1)...\n");
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = NVME_CMD_EBPF_LOAD;
    sqe.cid = 1;
    sqe.prp1 = 0; // Use default embedded program
    if (submit_nvme_cmd(qmem, &sqe, &cqe, 1000) != 0 || cqe.status != 0) {
        printf("[HOST ERROR] LOAD command failed! (status=0x%x)\n", cqe.status);
        goto cleanup;
    }
    printf("[HOST <- DEV] LOAD completed successfully (cid=%d, status=0x%x)\n", cqe.cid, cqe.status);

    // 5. Send TP4091 Command 2: ACTIVATE (JIT Compilation)
    printf("\n[HOST -> DEV] Submitting NVME_CMD_EBPF_ACTIVATE (cid=2)...\n");
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = NVME_CMD_EBPF_ACTIVATE;
    sqe.cid = 2;
    if (submit_nvme_cmd(qmem, &sqe, &cqe, 1000) != 0 || cqe.status != 0) {
        printf("[HOST ERROR] ACTIVATE command failed! (status=0x%x)\n", cqe.status);
        goto cleanup;
    }
    printf("[HOST <- DEV] ACTIVATE completed (JIT compiled) (cid=%d, status=0x%x)\n", cqe.cid, cqe.status);

    // 6. Send TP4091 Command 3: EXECUTE (Run on SLM context)
    printf("\n[HOST -> DEV] Submitting NVME_CMD_EBPF_EXECUTE (cid=3, ctx=0x222500000)...\n");
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = NVME_CMD_EBPF_EXECUTE;
    sqe.cid = 3;
    sqe.prp1 = 0x222500000ULL; // Physical SLM address of analytics_context
    if (submit_nvme_cmd(qmem, &sqe, &cqe, 1000) != 0 || cqe.status != 0) {
        printf("[HOST ERROR] EXECUTE command failed! (status=0x%x)\n", cqe.status);
        goto cleanup;
    }
    printf("[HOST <- DEV] EXECUTE completed! (cid=%d, status=0x%x)\n", cqe.cid, cqe.status);
    printf("\n====================================================\n");
    printf(">>> NVMe COMPUTATIONAL RESULT (CDW0): %u MATCHES <<<\n", cqe.cdw0);
    printf("--- Subsystem Local Memory (SLM) Aggregations ---\n");
    printf("  Matches (written to SLM): %u\n", slm_ctx->matches);
    printf("  Sum of matched amounts:   $%u\n", slm_ctx->sum_amount);
    printf("  Min matched amount:       $%u\n", slm_ctx->min_matched_amount);
    printf("  Max matched amount:       $%u\n", slm_ctx->max_matched_amount);
    printf("====================================================\n\n");

    // 7. Send TP4091 Command 4: SHUTDOWN (Park Core 3)
    printf("[HOST -> DEV] Submitting NVME_CMD_SHUTDOWN (cid=4)...\n");
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = NVME_CMD_SHUTDOWN;
    sqe.cid = 4;
    if (submit_nvme_cmd(qmem, &sqe, &cqe, 1000) == 0) {
        printf("[HOST <- DEV] SHUTDOWN acknowledged by Core 3.\n");
    }

    // Drain any remaining console output from Core 3 shutdown
    usleep(20000);
    drain_vcon();

cleanup:
    munmap(map_base, MAP_SIZE);
    close(mem_fd);
    printf("[HOST] Done.\n");
    return 0;
}
