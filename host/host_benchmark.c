#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <math.h>

#include "nvme_spec.h"
#include "nvme_queue.h"

static inline double calc_mean(const double *arr, int n) {
    if (n <= 0) return 0.0;
    double sum = 0.0;
    for (int i = 0; i < n; i++) sum += arr[i];
    return sum / n;
}

static inline double calc_std(const double *arr, int n, double mean) {
    if (n <= 1) return 0.0;
    double sum_sq = 0.0;
    for (int i = 0; i < n; i++) {
        double d = arr[i] - mean;
        sum_sq += d * d;
    }
    return sqrt(sum_sq / (n - 1));
}

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
    bool do_shutdown = false;
    const char *app_bin_path = "apps/analytics_simple.bin";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--shutdown") == 0) {
            do_shutdown = true;
        } else if (argv[i][0] != '-') {
            app_bin_path = argv[i];
        }
    }

    if (access(app_bin_path, F_OK) != 0 && argc <= 1) {
        app_bin_path = "../apps/analytics_simple.bin";
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

    // Boot or reuse Core 3
    if (qmem->regs.status == NVME_STATUS_READY) {
        printf("[BENCH] Core 3 is ALREADY alive and READY! Reusing active CSD...\n");
        qmem->regs.sq_tail = qmem->regs.sq_head;
        qmem->regs.cq_head = qmem->regs.cq_tail;
        __sync_synchronize();
    } else {
        *vcon_idx = 0;
        memset((void *)vcon_buf, 0, VCON_SIZE - 4);
        memset((void *)qmem, 0, sizeof(struct nvme_queue_mem));

        printf("[BENCH] Injecting firmware into RAM...\n");
        fw_fd = open(FW_BINARY, O_RDONLY);
        if (fw_fd < 0) fw_fd = open("../" FW_BINARY, O_RDONLY);
        if (fw_fd >= 0) {
            ssize_t bytes_read = read(fw_fd, map_base, 0x100000);
            close(fw_fd);
            printf("[BENCH] Firmware injected (%zd bytes).\n", bytes_read);
        } else {
            printf("[BENCH WARNING] Could not open firmware binary! Skipping injection.\n");
        }

        // Ensure Core 3 is offline in Linux
        (void)system("sh -c 'echo 0 > /sys/devices/system/cpu/cpu3/online 2>/dev/null'");
        (void)system("rmmod vf2_kick 2>/dev/null");

        printf("[BENCH] Kicking Core 3 via OpenSBI HSM...\n");
        int ins_ret = system("insmod tools/kick_core/vf2_kick.ko 2>/dev/null");
        if (ins_ret != 0) {
            ins_ret = system("insmod ../tools/kick_core/vf2_kick.ko 2>/dev/null");
        }
        if (ins_ret != 0) {
            fprintf(stderr, "[BENCH WARNING] insmod vf2_kick failed! Check 'dmesg | tail'.\n");
        }

        printf("[BENCH] Waiting for Core 3 boot...\n");
        int wait_count = 0;
        while (qmem->regs.status != NVME_STATUS_READY) {
            drain_vcon();
            usleep(10000);
            if (++wait_count > 1000) {
                fprintf(stderr, "\n[BENCH ERROR] Timeout waiting for Core 3 READY status!\n");
                munmap(map_base, MAP_SIZE);
                close(mem_fd);
                return 1;
            }
        }
        drain_vcon();
        printf("[BENCH] Core 3 READY detected!\n\n");
    }

    // Load eBPF application binary from disk into SLM
    printf("[BENCH] Loading eBPF program from '%s'...\n", app_bin_path);
    app_fd = open(app_bin_path, O_RDONLY);
    if (app_fd < 0) {
        perror("open app binary");
        return 1;
    }
    ssize_t prog_bytes = read(app_fd, slm_prog, 0x10000);
    close(app_fd);
    uint32_t num_inst = prog_bytes / 8;
    printf("[BENCH] Injected %zd bytes (%u instructions) into SLM (0x%llx).\n\n",
           prog_bytes, num_inst, (unsigned long long)SLM_PROG_PHYS_ADDR);

    struct nvme_sqe sqe = {0};
    struct nvme_cqe cqe = {0};
    uint16_t cid = 1;
    int ctrl_runs = 20;

    // --- MEASUREMENT 1: LOAD Command Latency (Sampled over 20 runs) ---
    double load_times[ctrl_runs];
    for (int i = 0; i < ctrl_runs; i++) {
        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = NVME_CMD_EBPF_LOAD;
        sqe.flags = NVME_FLAG_SILENT;
        sqe.cid = cid++;
        sqe.prp1 = SLM_PROG_PHYS_ADDR;
        sqe.cdw10 = num_inst;

        double t0 = get_time_us();
        bench_submit_poll(qmem, &sqe, &cqe);
        load_times[i] = get_time_us() - t0;
    }
    double load_mean = calc_mean(load_times, ctrl_runs);
    double load_std = calc_std(load_times, ctrl_runs, load_mean);
    printf("[1. LOAD]     Command Round-Trip Time: %.2f ± %.2f us (n=%d, Status: 0x%x)\n",
           load_mean, load_std, ctrl_runs, cqe.status);

    // --- MEASUREMENT 2: ACTIVATE (JIT Compilation) Latency (Sampled over 20 runs) ---
    double act_times[ctrl_runs];
    double act_cycles[ctrl_runs];
    for (int i = 0; i < ctrl_runs; i++) {
        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = NVME_CMD_EBPF_ACTIVATE;
        sqe.flags = NVME_FLAG_SILENT;
        sqe.cid = cid++;

        double t0 = get_time_us();
        bench_submit_poll(qmem, &sqe, &cqe);
        act_times[i] = get_time_us() - t0;
        act_cycles[i] = (double)cqe.rsvd1;
    }
    double act_mean = calc_mean(act_times, ctrl_runs);
    double act_std = calc_std(act_times, ctrl_runs, act_mean);
    double cycles_mean = calc_mean(act_cycles, ctrl_runs);
    double cycles_std = calc_std(act_cycles, ctrl_runs, cycles_mean);
    printf("[2. ACTIVATE] JIT Compilation Time:    %.2f ± %.2f us (Hardware Cycles: %.0f ± %.0f)\n",
           act_mean, act_std, cycles_mean, cycles_std);
    printf("              Average per instruction: %.2f cycles/inst\n\n", cycles_mean / num_inst);

    // --- MEASUREMENT 3: EXECUTION SCALING (Host vs Core 3 CSD) ---
    uint32_t dataset_sizes[] = { 100, 1000, 5000, 10000, 25000, 50000, 100000 };
    int num_sizes = sizeof(dataset_sizes) / sizeof(dataset_sizes[0]);
    int repetitions = 10;

    FILE *csv = fopen("benchmark_results.csv", "w");
    if (csv) {
        fprintf(csv, "records,data_kb,host_us,host_std_us,csd_us,csd_std_us,csd_cycles,csd_cycles_std,speedup,csd_throughput_mrec_s,csd_throughput_mb_s,csd_throughput_std_mb_s\n");
    }

    printf("-------------------------------------------------------------------------------------------------------------------------\n");
    printf("%-8s | %-8s | %-16s | %-16s | %-14s | %-8s | %-14s\n",
           "Records", "Size(KB)", "Host Time (us)", "CSD Time (us)", "CSD Cycles", "Speedup", "Throughput");
    printf("-------------------------------------------------------------------------------------------------------------------------\n");

    for (int s = 0; s < num_sizes; s++) {
        uint32_t n = dataset_sizes[s];
        double data_kb = (double)(n * sizeof(struct record)) / 1024.0;

        populate_dataset(slm_ctx, n);

        // Warmup run for Host
        (void)run_host_baseline(slm_ctx);

        // Host Native timing
        double host_runs[repetitions];
        uint32_t host_matches = 0;
        for (int r = 0; r < repetitions; r++) {
            double t0 = get_time_us();
            host_matches = run_host_baseline(slm_ctx);
            host_runs[r] = get_time_us() - t0;
        }
        double host_avg_us = calc_mean(host_runs, repetitions);
        double host_std_us = calc_std(host_runs, repetitions, host_avg_us);

        // CSD NVMe Offload timing
        double csd_runs[repetitions];
        double csd_cycles_runs[repetitions];
        double csd_thru_runs[repetitions];
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
            double elap = get_time_us() - t0;
            csd_runs[r] = elap;
            csd_cycles_runs[r] = (double)cqe.rsvd1;
            csd_thru_runs[r] = (data_kb / 1024.0) / (elap / 1000000.0);
            csd_matches = cqe.cdw0;
        }

        double csd_avg_us = calc_mean(csd_runs, repetitions);
        double csd_std_us = calc_std(csd_runs, repetitions, csd_avg_us);

        double csd_avg_cycles = calc_mean(csd_cycles_runs, repetitions);
        double csd_std_cycles = calc_std(csd_cycles_runs, repetitions, csd_avg_cycles);

        double csd_avg_thru = calc_mean(csd_thru_runs, repetitions);
        double csd_std_thru = calc_std(csd_thru_runs, repetitions, csd_avg_thru);

        double speedup = host_avg_us / csd_avg_us;
        double throughput_mrec_s = ((double)n / csd_avg_us);

        // Verify correctness
        if (host_matches != csd_matches) {
            printf("[WARNING] Result mismatch! Host=%u, CSD=%u\n", host_matches, csd_matches);
        }

        char host_buf[32], csd_buf[32], cyc_buf[32], thru_buf[32];
        snprintf(host_buf, sizeof(host_buf), "%.1f±%.1f", host_avg_us, host_std_us);
        snprintf(csd_buf, sizeof(csd_buf), "%.1f±%.1f", csd_avg_us, csd_std_us);
        snprintf(cyc_buf, sizeof(cyc_buf), "%.0f±%.0f", csd_avg_cycles, csd_std_cycles);
        snprintf(thru_buf, sizeof(thru_buf), "%.1f±%.1f", csd_avg_thru, csd_std_thru);

        printf("%-8u | %-8.1f | %-16s | %-16s | %-14s | %-7.2fx | %-14s\n",
               n, data_kb, host_buf, csd_buf, cyc_buf, speedup, thru_buf);

        if (csv) {
            fprintf(csv, "%u,%.2f,%.2f,%.2f,%.2f,%.2f,%.0f,%.0f,%.3f,%.2f,%.2f,%.2f\n",
                    n, data_kb, host_avg_us, host_std_us, csd_avg_us, csd_std_us,
                    csd_avg_cycles, csd_std_cycles, speedup, throughput_mrec_s, csd_avg_thru, csd_std_thru);
        }
    }

    printf("-------------------------------------------------------------------------------------------------------------------------\n");
    if (csv) {
        fclose(csv);
        printf("[BENCH] Full results written to 'benchmark_results.csv'.\n");
    }

    // Clean shutdown if requested
    if (do_shutdown) {
        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = NVME_CMD_SHUTDOWN;
        sqe.flags = NVME_FLAG_SILENT;
        sqe.cid = cid++;
        bench_submit_poll(qmem, &sqe, &cqe);
        qmem->regs.status = 0;
        __sync_synchronize();
        printf("[BENCH] Core 3 parked via SBI HSM.\n");
    } else {
        printf("[BENCH] Core 3 kept alive and READY for subsequent benchmarks.\n");
    }

    munmap(map_base, MAP_SIZE);
    close(mem_fd);
    return 0;
}
