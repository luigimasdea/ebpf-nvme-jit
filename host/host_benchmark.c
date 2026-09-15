#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>

#include "nvme_spec.h"
#include "nvme_queue.h"

#define PHYS_BASE           0x222000000ULL
#define MAP_SIZE            0x01000000ULL  // 16MB
#define FW_BINARY           "firmware/build/firmware.bin"

#define VCON_OFFSET         0x00400000ULL  // 0x222400000 (Virtual Console)
#define VCON_SIZE           4096

#define NVME_QUEUE_OFFSET   0x00401000ULL  // 0x222401000 (NVMe Queues)

// Subsystem Local Memory (SLM)
#define SLM_PROG_OFFSET     0x00500000ULL  // 0x222500000 (eBPF Bytecode buffer)
#define SLM_DATA_OFFSET     0x00510000ULL  // 0x222510000 (Dataset buffer)

#define SLM_PROG_PHYS_ADDR  (PHYS_BASE + SLM_PROG_OFFSET)
#define SLM_DATA_PHYS_ADDR  (PHYS_BASE + SLM_DATA_OFFSET)

// Dataset Record structure (16 bytes per record)
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
    struct record records[];
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

static inline double get_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000000.0 + (double)ts.tv_nsec / 1000.0;
}

/**
 * High-performance NVMe command submission & polling (zero sleep).
 */
static inline int bench_submit_poll(volatile struct nvme_queue_mem *qmem,
                                    struct nvme_sqe *cmd,
                                    struct nvme_cqe *out_cqe) {
    uint32_t tail = qmem->regs.sq_tail;
    uint32_t sq_idx = tail % NVME_QUEUE_DEPTH;

    qmem->sq[sq_idx] = *cmd;
    __sync_synchronize();

    // Ring Doorbell
    qmem->regs.sq_tail = tail + 1;
    __sync_synchronize();

    // High-speed busy-wait polling with timeout guard
    uint64_t max_spins = 100000000ULL;
    while (qmem->regs.cq_tail == qmem->regs.cq_head) {
        if (--max_spins == 0) {
            printf("[BENCH ERROR] Command cid=%u timed out waiting for CQE!\n", cmd->cid);
            return -1;
        }
    }

    __sync_synchronize();
    uint32_t cq_idx = qmem->regs.cq_head % NVME_QUEUE_DEPTH;
    *out_cqe = qmem->cq[cq_idx];

    // Release completion entry
    qmem->regs.cq_head++;
    __sync_synchronize();

    return 0;
}

/**
 * Host Native Baseline Implementation in C.
 */
static uint32_t run_host_baseline(struct analytics_context *ctx) {
    uint32_t n = ctx->record_count;
    uint32_t target_type = ctx->target_type;
    uint32_t min_amt = ctx->min_amount;
    uint32_t max_amt = ctx->max_amount;

    uint32_t match_count = 0;
    uint32_t sum = 0;
    uint32_t max_val = 0;
    uint32_t min_val = 0xFFFFFFFF;

    for (uint32_t i = 0; i < n; i++) {
        uint32_t r_type = ctx->records[i].type;
        uint32_t r_amt = ctx->records[i].amount;

        if (r_type == target_type && r_amt >= min_amt && r_amt <= max_amt) {
            match_count++;
            sum += r_amt;
            if (r_amt > max_val) max_val = r_amt;
            if (r_amt < min_val) min_val = r_amt;
        }
    }

    if (match_count == 0) min_val = 0;
    ctx->matches = match_count;
    ctx->sum_amount = sum;
    ctx->max_matched_amount = max_val;
    ctx->min_matched_amount = min_val;

    return match_count;
}

static void populate_dataset(struct analytics_context *ctx, uint32_t count) {
    ctx->record_count = count;
    ctx->target_type = 1;     // Filter for Type == 1 (SALE)
    ctx->min_amount = 100;    // Amount in [100, 500]
    ctx->max_amount = 500;
    ctx->matches = 0;
    ctx->sum_amount = 0;
    ctx->max_matched_amount = 0;
    ctx->min_matched_amount = 0;

    for (uint32_t i = 0; i < count; i++) {
        ctx->records[i].id = i + 1;
        ctx->records[i].type = (i % 3) + 1;         // Cyclic 1, 2, 3
        ctx->records[i].amount = (i * 37) % 600;    // Deterministic distribution
        ctx->records[i].timestamp = 1700000000 + i;
    }
}

int main(int argc, char *argv[]) {
    int mem_fd, fw_fd, app_fd;
    uint8_t *map_base;
    const char *app_bin_path = (argc > 1) ? argv[1] : "apps/app.bin";

    printf("========================================================================\n");
    printf("     VisionFive 2 eBPF-NVMe Computational Storage Micro-Benchmark       \n");
    printf("========================================================================\n");

    if (access(app_bin_path, F_OK) != 0 && argc <= 1) {
        app_bin_path = "../apps/app.bin";
    }

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

    vcon_idx = (volatile uint32_t *)(map_base + VCON_OFFSET + VCON_SIZE - 4);
    vcon_buf = (volatile char *)(map_base + VCON_OFFSET);
    volatile struct nvme_queue_mem *qmem = (volatile struct nvme_queue_mem *)(map_base + NVME_QUEUE_OFFSET);
    uint8_t *slm_prog = map_base + SLM_PROG_OFFSET;
    struct analytics_context *slm_ctx = (struct analytics_context *)(map_base + SLM_DATA_OFFSET);

    // 1. Reset memory and Queues
    printf("[BENCH] Resetting VCON and NVMe queues...\n");
    *vcon_idx = 0;
    memset((void*)vcon_buf, 0, VCON_SIZE - 4);
    memset((void*)qmem, 0, sizeof(struct nvme_queue_mem));

    // 2. Load eBPF application binary from disk into SLM
    printf("[BENCH] Loading eBPF program from '%s'...\n", app_bin_path);
    app_fd = open(app_bin_path, O_RDONLY);
    if (app_fd < 0) {
        perror("open app binary");
        return 1;
    }
    ssize_t prog_bytes = read(app_fd, slm_prog, 0x10000);
    close(app_fd);
    uint32_t num_inst = prog_bytes / 8;
    printf("[BENCH] Injected %zd bytes (%u instructions) into SLM (0x%llx).\n",
           prog_bytes, num_inst, (unsigned long long)SLM_PROG_PHYS_ADDR);

    // 3. Inject firmware binary
    printf("[BENCH] Injecting firmware into RAM...\n");
    fw_fd = open(FW_BINARY, O_RDONLY);
    if (fw_fd < 0) fw_fd = open("../" FW_BINARY, O_RDONLY);
    if (fw_fd >= 0) {
        read(fw_fd, map_base, 0x100000);
        close(fw_fd);
    } else {
        printf("[BENCH WARNING] Could not open firmware binary! Skipping injection.\n");
    }

    printf("[BENCH] Waiting for Core 3 boot... (insmod vf2_kick.ko now)\n");
    while (qmem->regs.status != NVME_STATUS_READY) {
        drain_vcon();
        usleep(5000);
    }
    drain_vcon();
    printf("[BENCH] Core 3 READY detected!\n\n");

    struct nvme_sqe sqe = {0};
    struct nvme_cqe cqe = {0};
    uint16_t cid = 1;

    // --- MEASUREMENT 1: LOAD Command Latency ---
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = NVME_CMD_EBPF_LOAD;
    sqe.flags = NVME_FLAG_SILENT;
    sqe.cid = cid++;
    sqe.prp1 = SLM_PROG_PHYS_ADDR;
    sqe.cdw10 = num_inst;

    double t_load_start = get_time_us();
    bench_submit_poll(qmem, &sqe, &cqe);
    double t_load_us = get_time_us() - t_load_start;
    printf("[1. LOAD]     Command Round-Trip Time: %.2f us (Status: 0x%x)\n", t_load_us, cqe.status);

    // --- MEASUREMENT 2: ACTIVATE (JIT Compilation) Latency ---
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = NVME_CMD_EBPF_ACTIVATE;
    sqe.flags = NVME_FLAG_SILENT;
    sqe.cid = cid++;

    double t_act_start = get_time_us();
    bench_submit_poll(qmem, &sqe, &cqe);
    double t_act_us = get_time_us() - t_act_start;
    uint32_t jit_cycles = cqe.rsvd1;
    printf("[2. ACTIVATE] JIT Compilation Time:    %.2f us (Hardware Cycles: %u)\n", t_act_us, jit_cycles);
    printf("              Average per instruction: %.2f cycles/inst\n\n", (double)jit_cycles / num_inst);

    // --- MEASUREMENT 3: EXECUTION SCALING (Host vs Core 3 CSD) ---
    uint32_t dataset_sizes[] = { 100, 1000, 5000, 10000, 25000, 50000, 100000 };
    int num_sizes = sizeof(dataset_sizes) / sizeof(dataset_sizes[0]);
    int repetitions = 10;

    FILE *csv = fopen("benchmark_results.csv", "w");
    if (csv) {
        fprintf(csv, "records,data_kb,host_us,csd_us,csd_cycles,speedup,csd_throughput_mrec_s,csd_throughput_mb_s\n");
    }

    printf("----------------------------------------------------------------------------------------------------\n");
    printf("%-8s | %-8s | %-12s | %-12s | %-12s | %-8s | %-12s\n",
           "Records", "Size(KB)", "Host Time(us)", "CSD Time(us)", "CSD Cycles", "Speedup", "Throughput");
    printf("----------------------------------------------------------------------------------------------------\n");

    for (int s = 0; s < num_sizes; s++) {
        uint32_t n = dataset_sizes[s];
        double data_kb = (double)(n * sizeof(struct record)) / 1024.0;

        populate_dataset(slm_ctx, n);

        // Host Native timing
        double host_total_us = 0.0;
        uint32_t host_matches = 0;
        for (int r = 0; r < repetitions; r++) {
            double t0 = get_time_us();
            host_matches = run_host_baseline(slm_ctx);
            host_total_us += (get_time_us() - t0);
        }
        double host_avg_us = host_total_us / repetitions;

        // CSD NVMe Offload timing
        double csd_total_us = 0.0;
        uint64_t csd_total_cycles = 0;
        uint32_t csd_matches = 0;

        // Warmup run
        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = NVME_CMD_EBPF_EXECUTE;
        sqe.flags = NVME_FLAG_SILENT;
        sqe.cid = cid++;
        sqe.prp1 = SLM_DATA_PHYS_ADDR;
        bench_submit_poll(qmem, &sqe, &cqe);

        for (int r = 0; r < repetitions; r++) {
            memset(&sqe, 0, sizeof(sqe));
            sqe.opcode = NVME_CMD_EBPF_EXECUTE;
            sqe.flags = NVME_FLAG_SILENT;
            sqe.cid = cid++;
            sqe.prp1 = SLM_DATA_PHYS_ADDR;

            double t0 = get_time_us();
            bench_submit_poll(qmem, &sqe, &cqe);
            csd_total_us += (get_time_us() - t0);
            csd_total_cycles += cqe.rsvd1;
            csd_matches = cqe.cdw0;
        }

        double csd_avg_us = csd_total_us / repetitions;
        uint32_t csd_avg_cycles = (uint32_t)(csd_total_cycles / repetitions);
        double speedup = host_avg_us / csd_avg_us;
        double throughput_mrec_s = ((double)n / csd_avg_us);
        double throughput_mb_s = (data_kb / 1024.0) / (csd_avg_us / 1000000.0);

        // Verify correctness
        if (host_matches != csd_matches) {
            printf("[WARNING] Result mismatch! Host=%u, CSD=%u\n", host_matches, csd_matches);
        }

        printf("%-8u | %-8.1f | %-12.2f | %-12.2f | %-12u | %-7.2fx | %-6.1f MB/s\n",
               n, data_kb, host_avg_us, csd_avg_us, csd_avg_cycles, speedup, throughput_mb_s);

        if (csv) {
            fprintf(csv, "%u,%.2f,%.2f,%.2f,%u,%.3f,%.2f,%.2f\n",
                    n, data_kb, host_avg_us, csd_avg_us, csd_avg_cycles, speedup, throughput_mrec_s, throughput_mb_s);
        }
    }

    printf("----------------------------------------------------------------------------------------------------\n");
    if (csv) {
        fclose(csv);
        printf("[BENCH] Full results written to 'benchmark_results.csv'.\n");
    }

    // Clean shutdown
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = NVME_CMD_SHUTDOWN;
    sqe.flags = NVME_FLAG_SILENT;
    sqe.cid = cid++;
    bench_submit_poll(qmem, &sqe, &cqe);
    printf("[BENCH] Core 3 parked via SBI HSM.\n");

    munmap(map_base, MAP_SIZE);
    close(mem_fd);
    return 0;
}
