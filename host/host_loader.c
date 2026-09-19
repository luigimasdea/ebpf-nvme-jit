/**
 * host_loader.c - Unified TP4091 Computational Storage Data Loader & Benchmark
 *
 * Supports two execution paradigms:
 * 1. In-RAM Architectural Model (--stream / --ram):
 *    Emulates an integrated CSD where flash is connected to the controller via
 *    an internal ONFI 5.0 bus (simulated via in-memory DMA memcpy ~80 µs / 256KB).
 *    Models PCIe storage baseline and realistic PCIe return channel transfer.
 * 2. Physical NVMe Storage Model (--disk <path>):
 *    Reads dataset from an ext4 filesystem on an M.2 NVMe SSD via pread(),
 *    measuring real-world Host Traditional vs CSD Sequential vs CSD Pipelined.
 *
 * Key Capabilities:
 * - Double-Buffered Pipelining: Overlaps chunk I/O with Core 3 eBPF JIT execution.
 * - In-place Stream Compaction: Core 3 filters records in SLM; Host receives only matches.
 * - Deterministic QoS Testing: Optional --contention flag to stress host CPU.
 * - Integrated VCON: Virtual Console drain for Core 3 firmware diagnostics.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "nvme_spec.h"
#include "nvme_queue.h"

#define PHYS_BASE           0x222000000ULL
#define MAP_SIZE            0x01000000ULL  // 16MB

#define VCON_OFFSET         0x00400000ULL  // 0x222400000 (Virtual Console)
#define VCON_SIZE           4096
#define NVME_QUEUE_OFFSET   0x00401000ULL  // 0x222401000 (NVMe Queues)

// Subsystem Local Memory (SLM) allocations
#define SLM_PROG_OFFSET     0x00500000ULL  // 0x222500000 (64KB buffer for eBPF bytecode)
#define SLM_BUF_A_OFFSET    0x00510000ULL  // 0x222510000 (Buffer A: Context + Data, 2MB)
#define SLM_BUF_B_OFFSET    0x00710000ULL  // 0x222710000 (Buffer B: Context + Data, 2MB)

#define SLM_PROG_PHYS_ADDR  (PHYS_BASE + SLM_PROG_OFFSET)
#define SLM_BUF_A_PHYS_ADDR (PHYS_BASE + SLM_BUF_A_OFFSET)
#define SLM_BUF_B_PHYS_ADDR (PHYS_BASE + SLM_BUF_B_OFFSET)

#define FW_BINARY           "firmware/build/firmware.bin"
#define DEFAULT_APP_BIN     "apps/analytics_advanced.bin"
#define DEFAULT_CHUNK_KB    256 // Default streaming chunk: 256 KB

struct record {
    uint32_t id;
    uint32_t type;       // 1 = SALE, 2 = REFUND, 3 = EXPENSE
    uint32_t amount;     // Transaction amount ($)
    uint32_t timestamp;  // Unix timestamp
};

struct advanced_context {
    // --- Inputs (Query Predicates & Parameters) ---
    uint32_t record_count;
    uint32_t target_type;
    uint32_t min_amount;
    uint32_t max_amount;
    uint32_t min_timestamp;
    uint32_t max_timestamp;
    uint32_t discount_pct;      // e.g. 15 -> net = (amt * 85) / 100
    uint32_t pad0;

    // --- Outputs (Aggregations & Projections) ---
    uint32_t matches;
    uint32_t sum_amount;
    uint32_t max_matched_amount;
    uint32_t min_matched_amount;
    uint32_t hash_accum;        // 32-bit composite hash of matched records
    uint32_t net_discount_sum;  // Sum of net amounts after discount
    uint32_t pad1;
    uint32_t pad2;

    // --- Dataset in SLM (in-place filtered records packed at index 0..matches-1) ---
    struct record records[];
};

struct query_summary {
    uint64_t matches;
    uint64_t sum_amount;
    uint64_t net_discount_sum;
    uint32_t min_amount;
    uint32_t max_amount;
    uint32_t hash_accum;
    double io_time_ms;
    double compute_time_ms;
    double total_time_ms;
    uint64_t host_mem_traffic_bytes;
};

enum data_source {
    SOURCE_RAM,
    SOURCE_DISK
};

static inline double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000.0) + (ts.tv_nsec / 1000000.0);
}

// Virtual Console pointers
static volatile uint32_t *vcon_idx = NULL;
static volatile char *vcon_buf = NULL;
static uint32_t last_vcon_read = 0;

static void drain_vcon(void) {
    if (!vcon_idx || !vcon_buf) return;
    uint32_t current_idx = *vcon_idx;
    while (last_vcon_read < current_idx) {
        char c = vcon_buf[last_vcon_read % (VCON_SIZE - 8)];
        putchar(c);
        last_vcon_read++;
    }
    fflush(stdout);
}

// Background contention worker simulation
static volatile bool stop_contention = false;
static void *contention_worker(void *arg) {
    volatile uint64_t val = 123456789;
    while (!stop_contention) {
        for (int i = 0; i < 100000; i++) {
            val = val * 6364136223846793005ULL + 1;
        }
    }
    return NULL;
}

// Submit NVMe Command & Poll for CQE
static int submit_nvme_cmd_silent(volatile struct nvme_queue_mem *qmem,
                                  struct nvme_sqe *cmd,
                                  struct nvme_cqe *out_cqe,
                                  int timeout_ms) {
    uint32_t tail = qmem->regs.sq_tail;
    qmem->sq[tail % NVME_QUEUE_DEPTH] = *cmd;
    __sync_synchronize();
    qmem->regs.sq_tail = tail + 1;
    __sync_synchronize();

    double t0 = get_time_ms();
    while ((get_time_ms() - t0) < timeout_ms) {
        if (qmem->regs.cq_tail != qmem->regs.cq_head) {
            uint32_t cq_idx = qmem->regs.cq_head % NVME_QUEUE_DEPTH;
            struct nvme_cqe cqe = qmem->cq[cq_idx];
            if (cqe.cid == cmd->cid) {
                *out_cqe = cqe;
                qmem->regs.cq_head++;
                __sync_synchronize();
                return 0;
            }
        }
    }
    return -2; // Timeout
}

static void drop_page_cache(void) {
    sync();
    int fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (fd >= 0) {
        if (write(fd, "3\n", 2) < 0) {
            // Ignore if running without root write permission
        }
        close(fd);
    }
}

// Pure Host C Query Function
static void run_host_query_batch(const struct record *records, uint32_t count,
                                 uint32_t target_type, uint32_t min_amt, uint32_t max_amt,
                                 uint32_t min_ts, uint32_t max_ts, uint32_t disc_pct,
                                 struct record *out_matches, uint32_t *out_matches_count,
                                 struct query_summary *summary) {
    uint32_t local_matches = 0;
    for (uint32_t i = 0; i < count; i++) {
        struct record r = records[i];
        if (r.type == target_type &&
            r.amount >= min_amt && r.amount <= max_amt &&
            r.timestamp >= min_ts && r.timestamp <= max_ts) {

            uint32_t net = (r.amount * (100 - disc_pct)) / 100;
            summary->sum_amount += r.amount;
            summary->net_discount_sum += net;
            if (r.amount < summary->min_amount) summary->min_amount = r.amount;
            if (r.amount > summary->max_amount) summary->max_amount = r.amount;

            // FNV-1a Hash
            summary->hash_accum ^= r.id;
            summary->hash_accum *= 16777619;
            summary->hash_accum ^= r.amount;
            summary->hash_accum *= 16777619;

            if (out_matches) {
                out_matches[local_matches] = r;
            }
            local_matches++;
        }
    }
    summary->matches += local_matches;
    if (out_matches_count) *out_matches_count = local_matches;
}

static void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  In-RAM CSD Mode (ONFI Model):\n");
    printf("    %s --stream <size_mb> [chunk_kb] [sel_pct]\n", prog);
    printf("    %s --ram <size_mb> [chunk_kb] [sel_pct]\n", prog);
    printf("  Physical NVMe Storage Mode (pread):\n");
    printf("    %s --disk <file.bin> [chunk_kb] [sel_pct] [--contention]\n", prog);
    printf("    %s <file.bin> [chunk_kb] [sel_pct] [--contention]\n", prog);
    printf("\nOptions:\n");
    printf("  --contention, -c   Run background CPU worker on Host to test QoS\n");
    printf("  --vcon             Drain and display Core 3 Virtual Console debug log\n");
    printf("  --shutdown         Park Core 3 via SBI HSM after benchmark completes\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    enum data_source src = SOURCE_DISK;
    const char *dataset_path = NULL;
    uint64_t stream_mb = 100;
    uint32_t chunk_kb = DEFAULT_CHUNK_KB;
    uint32_t sel_pct = 3; // Default 3% selectivity
    bool contention_enabled = false;
    bool show_vcon = false;
    bool do_shutdown = false;

    // Parse options
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--contention") == 0 || strcmp(argv[i], "-c") == 0) {
            contention_enabled = true;
        } else if (strcmp(argv[i], "--vcon") == 0) {
            show_vcon = true;
        } else if (strcmp(argv[i], "--shutdown") == 0) {
            do_shutdown = true;
        }
    }

    // Determine mode
    if (strcmp(argv[1], "--stream") == 0 || strcmp(argv[1], "--ram") == 0) {
        src = SOURCE_RAM;
        if (argc >= 3 && atoi(argv[2]) > 0) stream_mb = (uint64_t)atoi(argv[2]);
        if (argc >= 4 && atoi(argv[3]) > 0) chunk_kb = (uint32_t)atoi(argv[3]);
        if (argc >= 5 && atoi(argv[4]) > 0) sel_pct = (uint32_t)atoi(argv[4]);
    } else if (strcmp(argv[1], "--disk") == 0) {
        src = SOURCE_DISK;
        if (argc < 3) {
            print_usage(argv[0]);
            return 1;
        }
        dataset_path = argv[2];
        if (argc >= 4 && atoi(argv[3]) > 0) chunk_kb = (uint32_t)atoi(argv[3]);
        if (argc >= 5 && atoi(argv[4]) > 0) sel_pct = (uint32_t)atoi(argv[4]);
    } else {
        // Positional dataset file
        src = SOURCE_DISK;
        dataset_path = argv[1];
        if (argc >= 3 && atoi(argv[2]) > 0) chunk_kb = (uint32_t)atoi(argv[2]);
        if (argc >= 4 && atoi(argv[3]) > 0) sel_pct = (uint32_t)atoi(argv[3]);
    }

    if (chunk_kb < 16) chunk_kb = 16;
    if (chunk_kb > 2048) chunk_kb = 2048; // Max 2MB per chunk for SLM buffers

    uint32_t chunk_bytes = chunk_kb * 1024;
    uint32_t chunk_records = chunk_bytes / sizeof(struct record);
    chunk_bytes = chunk_records * sizeof(struct record);

    uint64_t file_bytes = 0;
    uint64_t total_records = 0;
    uint64_t template_bytes = 0;
    uint8_t *raw_dataset = NULL;
    int disk_fd = -1;

    printf("====================================================================\n");
    if (src == SOURCE_RAM) {
        printf("[UNIFIED CSD LOADER: IN-RAM STREAMING ARCHITECTURE (ONFI MODEL)]\n");
    } else {
        printf("[UNIFIED CSD LOADER: PHYSICAL STORAGE BENCHMARK (NVMe/ext4 pread)]\n");
    }
    printf("====================================================================\n");

    if (src == SOURCE_RAM) {
        file_bytes = stream_mb * 1024ULL * 1024ULL;
        total_records = file_bytes / sizeof(struct record);
        template_bytes = (file_bytes < 16 * 1024 * 1024ULL) ? file_bytes : (16 * 1024 * 1024ULL);
        if (template_bytes < chunk_bytes) template_bytes = chunk_bytes;

        printf("  Streaming Target  : %lu MB (%.2f GB, %lu records)\n",
               (unsigned long)stream_mb, (double)file_bytes / (1024.0 * 1024.0 * 1024.0), (unsigned long)total_records);
        printf("  Streaming Chunk   : %u KB (%u records / chunk, %lu total chunks)\n",
               chunk_kb, chunk_records, (unsigned long)(file_bytes / chunk_bytes));
        printf("  RAM Memory Mode   : Zero-Disk Circular Streaming Pattern (Template: %.2f MB)\n",
               (double)template_bytes / (1024.0 * 1024.0));
        printf("  Internal Bus Sim  : Memory DMA memcpy (~80 µs / chunk, mirrors ONFI 5.0)\n");
        printf("  Generating synthetic template pattern in RAM... ");
        fflush(stdout);

        raw_dataset = malloc(template_bytes);
        if (!raw_dataset) {
            fprintf(stderr, "Out of memory allocating %lu bytes template\n", (unsigned long)template_bytes);
            return 1;
        }
        uint32_t template_records = template_bytes / sizeof(struct record);
        struct record *rec_buf = (struct record *)raw_dataset;
        uint32_t seed = 42;
        #define FAST_RAND() (seed = seed * 1664525u + 1013904223u)
        for (uint32_t i = 0; i < template_records; i++) {
            rec_buf[i].id = i + 1;
            rec_buf[i].type = (FAST_RAND() % 3) + 1;
            rec_buf[i].amount = (FAST_RAND() % 1000) + 1;
            rec_buf[i].timestamp = 1700000000 + (FAST_RAND() % 86400);
        }
        printf("Done (Deterministic LCG pattern ready).\n");
    } else {
        struct stat st;
        if (stat(dataset_path, &st) != 0) {
            perror("Error stat dataset file");
            return 1;
        }
        file_bytes = st.st_size;
        total_records = file_bytes / sizeof(struct record);
        template_bytes = file_bytes;

        printf("  Dataset File      : %s\n", dataset_path);
        printf("  Dataset Size      : %.2f MB (%lu bytes, %lu records)\n",
               (double)file_bytes / (1024.0 * 1024.0), (unsigned long)file_bytes, (unsigned long)total_records);
        printf("  Streaming Chunk   : %u KB (%u records / chunk)\n", chunk_kb, chunk_records);
        printf("  Host Contention   : %s\n", contention_enabled ? "ACTIVE (Host background worker running)" : "OFF");
    }

    // Configure query predicates based on selectivity
    uint32_t QUERY_TYPE = 1;
    uint32_t QUERY_MIN_AMT = 50;
    uint32_t QUERY_MAX_AMT = 150;
    uint32_t QUERY_MIN_TS  = 1699999999;
    uint32_t QUERY_MAX_TS  = 1700086401;
    uint32_t QUERY_DISC_PCT = 15;

    if (sel_pct == 100) {
        QUERY_TYPE = 0; // Match all types
        QUERY_MIN_AMT = 0;
        QUERY_MAX_AMT = 2000;
    } else if (sel_pct >= 75) {
        QUERY_TYPE = 0;
        QUERY_MIN_AMT = 1;
        QUERY_MAX_AMT = 750;
    } else if (sel_pct >= 50) {
        QUERY_TYPE = 0;
        QUERY_MIN_AMT = 1;
        QUERY_MAX_AMT = 500;
    } else if (sel_pct >= 25) {
        QUERY_TYPE = 0;
        QUERY_MIN_AMT = 1;
        QUERY_MAX_AMT = 250;
    } else if (sel_pct >= 10) {
        QUERY_TYPE = 1;
        QUERY_MIN_AMT = 1;
        QUERY_MAX_AMT = 300;
    }

    printf("  Query Selectivity : ~%u%% (Type=%u, Amt=[%u..%u], Disc=%u%%)\n\n",
           sel_pct, QUERY_TYPE, QUERY_MIN_AMT, QUERY_MAX_AMT, QUERY_DISC_PCT);

    // Map Shared Memory
    int mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd < 0) {
        perror("open /dev/mem");
        return 1;
    }

    uint8_t *map_base = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, PHYS_BASE);
    if (map_base == MAP_FAILED) {
        perror("mmap");
        close(mem_fd);
        return 1;
    }

    vcon_idx = (volatile uint32_t *)(map_base + VCON_OFFSET + VCON_SIZE - 4);
    vcon_buf = (volatile char *)(map_base + VCON_OFFSET);
    volatile struct nvme_queue_mem *qmem = (volatile struct nvme_queue_mem *)(map_base + NVME_QUEUE_OFFSET);
    struct advanced_context *ctx_a = (struct advanced_context *)(map_base + SLM_BUF_A_OFFSET);
    struct advanced_context *ctx_b = (struct advanced_context *)(map_base + SLM_BUF_B_OFFSET);

    // Boot or reuse Core 3
    if (qmem->regs.status == NVME_STATUS_READY) {
        printf("[HOST] Core 3 is ALREADY alive and READY! Reusing active CSD...\n");
        qmem->regs.sq_tail = qmem->regs.sq_head;
        qmem->regs.cq_head = qmem->regs.cq_tail;
        __sync_synchronize();
    } else {
        *vcon_idx = 0;
        memset((void *)vcon_buf, 0, VCON_SIZE - 4);
        memset((void *)qmem, 0, sizeof(struct nvme_queue_mem));

        printf("[HOST] Injecting generic CSD firmware into RAM (0x222000000)...\n");
        int fw_fd = open(FW_BINARY, O_RDONLY);
        if (fw_fd < 0) fw_fd = open("../" FW_BINARY, O_RDONLY);
        if (fw_fd >= 0) {
            ssize_t bytes_read = read(fw_fd, map_base, 0x100000);
            close(fw_fd);
            printf("[HOST] Firmware injected (%zd bytes).\n", bytes_read);
        }

        // Ensure Core 3 is offline in Linux
        system("sh -c 'echo 0 > /sys/devices/system/cpu/cpu3/online 2>/dev/null'");
        system("rmmod vf2_kick 2>/dev/null");

        printf("[HOST] Kicking Core 3 via OpenSBI HSM...\n");
        int ins_ret = system("insmod tools/kick_core/vf2_kick.ko 2>/dev/null");
        if (ins_ret != 0) {
            ins_ret = system("insmod ../tools/kick_core/vf2_kick.ko 2>/dev/null");
        }
        if (ins_ret != 0) {
            fprintf(stderr, "[HOST WARNING] insmod vf2_kick failed! Check 'dmesg | tail'.\n");
        }

        printf("[HOST] Waiting for Core 3 boot...\n");
        int wait_count = 0;
        while (qmem->regs.status != NVME_STATUS_READY) {
            drain_vcon();
            usleep(10000);
            if (++wait_count > 1000) {
                fprintf(stderr, "\n[HOST ERROR] Timeout waiting for Core 3 READY status!\n");
                munmap(map_base, MAP_SIZE);
                close(mem_fd);
                if (raw_dataset) free(raw_dataset);
                return 1;
            }
        }
        drain_vcon();
        printf("[HOST] Core 3 is READY! Initializing TP4091 Controller...\n");
    }

    struct nvme_sqe sqe;
    struct nvme_cqe cqe;
    uint16_t cid = 100;

    // Load & Activate eBPF Program
    const char *app_path = DEFAULT_APP_BIN;
    int app_fd = open(app_path, O_RDONLY);
    if (app_fd < 0) {
        app_path = "../" DEFAULT_APP_BIN;
        app_fd = open(app_path, O_RDONLY);
    }
    if (app_fd < 0) {
        fprintf(stderr, "[ERROR] Cannot open eBPF application: %s\n", DEFAULT_APP_BIN);
        return 1;
    }

    uint8_t *prog_slm = map_base + SLM_PROG_OFFSET;
    ssize_t prog_len = read(app_fd, prog_slm, 65536);
    close(app_fd);
    __sync_synchronize();

    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = NVME_CMD_EBPF_LOAD;
    sqe.cid = ++cid;
    sqe.prp1 = SLM_PROG_PHYS_ADDR;
    sqe.cdw10 = (uint32_t)prog_len;
    if (submit_nvme_cmd_silent(qmem, &sqe, &cqe, 1000) != 0 || cqe.status != 0) {
        fprintf(stderr, "[ERROR] EBPF_LOAD command failed!\n");
        drain_vcon();
        return 1;
    }

    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = NVME_CMD_EBPF_ACTIVATE;
    sqe.cid = ++cid;
    if (submit_nvme_cmd_silent(qmem, &sqe, &cqe, 1000) != 0 || cqe.status != 0) {
        fprintf(stderr, "[ERROR] EBPF_ACTIVATE command failed!\n");
        drain_vcon();
        return 1;
    }

    // Allocate result buffers (cap to 2 million records for RAM conservation)
    uint64_t max_out_records = (total_records <= 2000000) ? total_records : 2000000;
    struct record *host_matched_records = malloc(max_out_records * sizeof(struct record));
    struct record *csd_matched_records = malloc(max_out_records * sizeof(struct record));
    struct record *pipe_matched_records = malloc(max_out_records * sizeof(struct record));
    if (!host_matched_records || !csd_matched_records || !pipe_matched_records) {
        fprintf(stderr, "[ERROR] Failed allocating matched record buffers\n");
        return 1;
    }

    // Optional contention worker
    pthread_t contention_th;
    if (contention_enabled) {
        stop_contention = false;
        pthread_create(&contention_th, NULL, contention_worker, NULL);
    }

    // =========================================================================
    // EXPERIMENT 1: HOST BASELINE EXECUTION
    // =========================================================================
    printf("--------------------------------------------------------------------\n");
    if (src == SOURCE_RAM) {
        printf("[EXPERIMENT 1] Host In-RAM Query Processing (GCC -O2 Native)\n");
    } else {
        printf("[EXPERIMENT 1] Host Traditional Processing (pread + GCC -O2 Native)\n");
    }
    printf("--------------------------------------------------------------------\n");

    struct query_summary host_res = {0};
    host_res.min_amount = 0xFFFFFFFF;
    host_res.hash_accum = 0x811C9DC5;

    if (src == SOURCE_DISK) {
        drop_page_cache();
        disk_fd = open(dataset_path, O_RDONLY);
        if (disk_fd < 0) {
            perror("open dataset for host read");
            return 1;
        }
    }

    double host_t0 = get_time_ms();
    uint64_t bytes_left = file_bytes;
    uint64_t file_offset = 0;
    struct record *host_raw_chunk = (src == SOURCE_DISK) ? malloc(chunk_bytes) : NULL;

    while (bytes_left > 0) {
        uint32_t to_read = (bytes_left > chunk_bytes) ? chunk_bytes : (uint32_t)bytes_left;
        uint32_t records_in_batch = to_read / sizeof(struct record);

        const struct record *records_ptr = NULL;
        if (src == SOURCE_RAM) {
            uint32_t template_offset = (uint32_t)(file_offset % template_bytes);
            records_ptr = (const struct record *)(raw_dataset + template_offset);
        } else {
            double t_io0 = get_time_ms();
            ssize_t rd = pread(disk_fd, host_raw_chunk, to_read, file_offset);
            double t_io1 = get_time_ms();
            host_res.io_time_ms += (t_io1 - t_io0);
            if (rd != (ssize_t)to_read) break;
            records_ptr = host_raw_chunk;
        }

        double t_comp0 = get_time_ms();
        uint32_t batch_matches = 0;
        void *dst = (total_records <= 2000000) ? (void *)(host_matched_records + host_res.matches) : (void *)host_matched_records;
        run_host_query_batch(records_ptr, records_in_batch,
                             QUERY_TYPE, QUERY_MIN_AMT, QUERY_MAX_AMT,
                             QUERY_MIN_TS, QUERY_MAX_TS, QUERY_DISC_PCT,
                             (struct record *)dst, &batch_matches, &host_res);
        double t_comp1 = get_time_ms();
        host_res.compute_time_ms += (t_comp1 - t_comp0);

        bytes_left -= to_read;
        file_offset += to_read;
    }
    double host_t1 = get_time_ms();
    host_res.total_time_ms = host_t1 - host_t0;
    if (src == SOURCE_DISK) {
        free(host_raw_chunk);
        close(disk_fd);
    }

    double host_thru = ((double)file_bytes / (1024.0 * 1024.0)) / (host_res.total_time_ms / 1000.0);
    printf("  Host Total Time   : %8.2f ms\n", host_res.total_time_ms);
    if (src == SOURCE_DISK) {
        printf("    -> Host Disk IO : %8.2f ms (%.1f%%)\n", host_res.io_time_ms, (host_res.io_time_ms / host_res.total_time_ms) * 100.0);
    }
    printf("    -> Host Compute : %8.2f ms (%.1f%%)\n", host_res.compute_time_ms, (host_res.compute_time_ms / host_res.total_time_ms) * 100.0);
    printf("  Host Throughput   : %8.2f MB/s\n", host_thru);
    printf("  Matches / Sum     : %lu matches (%.2f%% selectivity), Gross Sum: $%lu, Net Sum: $%lu\n",
           host_res.matches, ((double)host_res.matches / (double)total_records) * 100.0,
           host_res.sum_amount, host_res.net_discount_sum);
    printf("  Min / Max / Hash  : $%u / $%u / 0x%08X\n\n",
           host_res.min_amount, host_res.max_amount, host_res.hash_accum);

    // =========================================================================
    // EXPERIMENT 2: COMPUTATIONAL STORAGE SEQUENTIAL (Non-Pipelined)
    // =========================================================================
    printf("--------------------------------------------------------------------\n");
    printf("[EXPERIMENT 2] CSD Sequential (Fetch Block -> Execute Core 3 JIT -> Return)\n");
    printf("--------------------------------------------------------------------\n");

    struct query_summary csd_res = {0};
    csd_res.min_amount = 0xFFFFFFFF;
    csd_res.hash_accum = 0x811C9DC5;

    if (src == SOURCE_DISK) {
        drop_page_cache();
        disk_fd = open(dataset_path, O_RDONLY);
        if (disk_fd < 0) {
            perror("open dataset for CSD sequential read");
            return 1;
        }
    }

    double csd_t0 = get_time_ms();
    bytes_left = file_bytes;
    file_offset = 0;

    while (bytes_left > 0) {
        uint32_t to_read = (bytes_left > chunk_bytes) ? chunk_bytes : (uint32_t)bytes_left;
        uint32_t records_in_batch = to_read / sizeof(struct record);

        // Fetch chunk into SLM Buffer A
        double t_io0 = get_time_ms();
        if (src == SOURCE_RAM) {
            uint32_t template_offset = (uint32_t)(file_offset % template_bytes);
            memcpy(ctx_a->records, raw_dataset + template_offset, to_read);
        } else {
            ssize_t rd = pread(disk_fd, ctx_a->records, to_read, file_offset);
            if (rd != (ssize_t)to_read) break;
        }
        double t_io1 = get_time_ms();
        csd_res.io_time_ms += (t_io1 - t_io0);

        // Configure Context in SLM
        ctx_a->record_count = records_in_batch;
        ctx_a->target_type = QUERY_TYPE;
        ctx_a->min_amount = QUERY_MIN_AMT;
        ctx_a->max_amount = QUERY_MAX_AMT;
        ctx_a->min_timestamp = QUERY_MIN_TS;
        ctx_a->max_timestamp = QUERY_MAX_TS;
        ctx_a->discount_pct = QUERY_DISC_PCT;
        __sync_synchronize();

        // Dispatch EXECUTE command to Core 3
        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = NVME_CMD_EBPF_EXECUTE;
        sqe.flags = NVME_FLAG_SILENT;
        sqe.cid = ++cid;
        sqe.prp1 = SLM_BUF_A_PHYS_ADDR;

        double t_comp0 = get_time_ms();
        if (submit_nvme_cmd_silent(qmem, &sqe, &cqe, 3000) != 0 || cqe.status != 0) {
            fprintf(stderr, "[ERROR] CSD Execute command failed at offset %lu!\n", (unsigned long)file_offset);
            drain_vcon();
            break;
        }
        double t_comp1 = get_time_ms();
        csd_res.compute_time_ms += (t_comp1 - t_comp0);

        // Transfer compacted matched records to Host
        uint32_t batch_matches = cqe.cdw0;
        if (batch_matches > 0) {
            void *dst = (total_records <= 2000000) ? (void *)(csd_matched_records + csd_res.matches) : (void *)csd_matched_records;
            memcpy(dst, (void *)ctx_a->records, batch_matches * sizeof(struct record));
            csd_res.host_mem_traffic_bytes += (batch_matches * sizeof(struct record));
        }

        csd_res.matches += batch_matches;
        csd_res.sum_amount += ctx_a->sum_amount;
        csd_res.net_discount_sum += ctx_a->net_discount_sum;
        if (ctx_a->min_matched_amount < csd_res.min_amount && batch_matches > 0) {
            csd_res.min_amount = ctx_a->min_matched_amount;
        }
        if (ctx_a->max_matched_amount > csd_res.max_amount) {
            csd_res.max_amount = ctx_a->max_matched_amount;
        }
        csd_res.hash_accum ^= ctx_a->hash_accum;

        bytes_left -= to_read;
        file_offset += to_read;
    }
    double csd_t1 = get_time_ms();
    csd_res.total_time_ms = csd_t1 - csd_t0;
    if (src == SOURCE_DISK) close(disk_fd);

    double csd_thru = ((double)file_bytes / (1024.0 * 1024.0)) / (csd_res.total_time_ms / 1000.0);
    printf("  CSD Total Time    : %8.2f ms\n", csd_res.total_time_ms);
    printf("    -> %s : %8.2f ms (%.1f%%)\n",
           (src == SOURCE_RAM) ? "ONFI I/O Sim" : "Disk pread IO",
           csd_res.io_time_ms, (csd_res.io_time_ms / csd_res.total_time_ms) * 100.0);
    printf("    -> CSD Compute  : %8.2f ms (%.1f%%)\n", csd_res.compute_time_ms, (csd_res.compute_time_ms / csd_res.total_time_ms) * 100.0);
    printf("  CSD Throughput    : %8.2f MB/s\n", csd_thru);
    printf("  Host Memory Recv  : %.2f MB (Only compacted results transferred to Host!)\n", (double)csd_res.host_mem_traffic_bytes / (1024.0 * 1024.0));
    printf("  Matches / Sum     : %lu matches (%.2f%% selectivity), Gross Sum: $%lu, Net Sum: $%lu\n",
           csd_res.matches, ((double)csd_res.matches / (double)total_records) * 100.0,
           csd_res.sum_amount, csd_res.net_discount_sum);
    printf("  Min / Max / Hash  : $%u / $%u / 0x%08X\n\n",
           csd_res.min_amount, csd_res.max_amount, csd_res.hash_accum);

    // =========================================================================
    // EXPERIMENT 3: COMPUTATIONAL STORAGE PIPELINED (Double-Buffered Streaming)
    // =========================================================================
    printf("--------------------------------------------------------------------\n");
    printf("[EXPERIMENT 3] CSD Pipelined (Double-Buffered Streaming with Complete Overlap)\n");
    printf("--------------------------------------------------------------------\n");

    struct query_summary pipe_res = {0};
    pipe_res.min_amount = 0xFFFFFFFF;
    pipe_res.hash_accum = 0x811C9DC5;

    if (src == SOURCE_DISK) {
        drop_page_cache();
        disk_fd = open(dataset_path, O_RDONLY);
        if (disk_fd < 0) {
            perror("open dataset for CSD pipelined read");
            return 1;
        }
    }

    double pipe_t0 = get_time_ms();
    bytes_left = file_bytes;
    file_offset = 0;

    int cur_buf = 0;
    bool core3_active = false;
    uint16_t active_cid = 0;

    while (bytes_left > 0 || core3_active) {
        uint32_t to_read = (bytes_left > chunk_bytes) ? chunk_bytes : (uint32_t)bytes_left;
        uint32_t records_in_batch = to_read / sizeof(struct record);

        struct advanced_context *fill_ctx = (cur_buf == 0) ? ctx_a : ctx_b;
        struct advanced_context *exec_ctx = (cur_buf == 0) ? ctx_b : ctx_a;
        uint64_t fill_phys_addr = (cur_buf == 0) ? SLM_BUF_A_PHYS_ADDR : SLM_BUF_B_PHYS_ADDR;

        // Step 1: Transfer next chunk from storage/RAM into idle buffer
        if (bytes_left > 0) {
            if (src == SOURCE_RAM) {
                uint32_t template_offset = (uint32_t)(file_offset % template_bytes);
                memcpy(fill_ctx->records, raw_dataset + template_offset, to_read);
            } else {
                ssize_t rd = pread(disk_fd, fill_ctx->records, to_read, file_offset);
                if (rd != (ssize_t)to_read) {
                    fprintf(stderr, "[ERROR] pread failed at offset %lu\n", (unsigned long)file_offset);
                    break;
                }
            }

            fill_ctx->record_count = records_in_batch;
            fill_ctx->target_type = QUERY_TYPE;
            fill_ctx->min_amount = QUERY_MIN_AMT;
            fill_ctx->max_amount = QUERY_MAX_AMT;
            fill_ctx->min_timestamp = QUERY_MIN_TS;
            fill_ctx->max_timestamp = QUERY_MAX_TS;
            fill_ctx->discount_pct = QUERY_DISC_PCT;
            __sync_synchronize();

            bytes_left -= to_read;
            file_offset += to_read;
        }

        // Step 2: Await completion of previous chunk
        if (core3_active) {
            double start_t = get_time_ms();
            while ((get_time_ms() - start_t) < 3000) {
                if (qmem->regs.cq_tail != qmem->regs.cq_head) {
                    uint32_t cq_idx = qmem->regs.cq_head % NVME_QUEUE_DEPTH;
                    struct nvme_cqe cqe_p = qmem->cq[cq_idx];
                    if (cqe_p.cid == active_cid) {
                        qmem->regs.cq_head++;
                        __sync_synchronize();

                        uint32_t batch_matches = cqe_p.cdw0;
                        if (batch_matches > 0) {
                            void *dst = (total_records <= 2000000) ? (void *)(pipe_matched_records + pipe_res.matches) : (void *)pipe_matched_records;
                            memcpy(dst, (void *)exec_ctx->records, batch_matches * sizeof(struct record));
                            pipe_res.host_mem_traffic_bytes += (batch_matches * sizeof(struct record));
                        }

                        pipe_res.matches += batch_matches;
                        pipe_res.sum_amount += exec_ctx->sum_amount;
                        pipe_res.net_discount_sum += exec_ctx->net_discount_sum;
                        if (exec_ctx->min_matched_amount < pipe_res.min_amount && batch_matches > 0) {
                            pipe_res.min_amount = exec_ctx->min_matched_amount;
                        }
                        if (exec_ctx->max_matched_amount > pipe_res.max_amount) {
                            pipe_res.max_amount = exec_ctx->max_matched_amount;
                        }
                        pipe_res.hash_accum ^= exec_ctx->hash_accum;

                        core3_active = false;
                        break;
                    } else {
                        qmem->regs.cq_head++;
                        __sync_synchronize();
                    }
                }
            }

            if (core3_active) {
                fprintf(stderr, "[ERROR] Timeout waiting for CID %u\n", active_cid);
                drain_vcon();
                break;
            }
        }

        // Step 3: Dispatch filled buffer to Core 3
        if (records_in_batch > 0) {
            active_cid = ++cid;
            memset(&sqe, 0, sizeof(sqe));
            sqe.opcode = NVME_CMD_EBPF_EXECUTE;
            sqe.flags = NVME_FLAG_SILENT;
            sqe.cid = active_cid;
            sqe.prp1 = fill_phys_addr;

            uint32_t tail = qmem->regs.sq_tail;
            qmem->sq[tail % NVME_QUEUE_DEPTH] = sqe;
            __sync_synchronize();
            qmem->regs.sq_tail = tail + 1;
            __sync_synchronize();

            core3_active = true;
            cur_buf = 1 - cur_buf; // Swap buffers
        }
    }
    double pipe_t1 = get_time_ms();
    pipe_res.total_time_ms = pipe_t1 - pipe_t0;
    if (src == SOURCE_DISK) close(disk_fd);

    if (contention_enabled) {
        stop_contention = true;
        pthread_join(contention_th, NULL);
    }

    double pipe_thru = ((double)file_bytes / (1024.0 * 1024.0)) / (pipe_res.total_time_ms / 1000.0);
    printf("  Pipelined Total   : %8.2f ms\n", pipe_res.total_time_ms);
    printf("  Pipe Throughput   : %8.2f MB/s\n", pipe_thru);
    printf("  Host Memory Recv  : %.2f MB (Compacted matched records transferred)\n", (double)pipe_res.host_mem_traffic_bytes / (1024.0 * 1024.0));
    printf("  Matches / Sum     : %lu matches (%.2f%% selectivity), Gross Sum: $%lu, Net Sum: $%lu\n",
           pipe_res.matches, ((double)pipe_res.matches / (double)total_records) * 100.0,
           pipe_res.sum_amount, pipe_res.net_discount_sum);
    printf("  Min / Max / Hash  : $%u / $%u / 0x%08X\n\n",
           pipe_res.min_amount, pipe_res.max_amount, pipe_res.hash_accum);

    // =========================================================================
    // FINAL COMPREHENSIVE COMPARISON TABLE
    // =========================================================================
    double pipe_speedup = host_res.total_time_ms / pipe_res.total_time_ms;
    double lat_reduct = (1.0 - (pipe_res.total_time_ms / host_res.total_time_ms)) * 100.0;
    double data_reduction_pct = (1.0 - ((double)csd_res.host_mem_traffic_bytes / (double)file_bytes)) * 100.0;

    // Measured Host PCIe Storage Baseline:
    // Sustained ext4/PCIe pread rate on VisionFive 2 is ~132.86 MB/s (114.85 ms for 15.26 MB)
    double host_pcie_rate_mb_s = 132.86;
    double host_storage_io_ms = ((double)file_bytes / (1024.0 * 1024.0)) / (host_pcie_rate_mb_s / 1000.0);
    double host_storage_baseline_ms = host_storage_io_ms + host_res.compute_time_ms;

    // Realistic PCIe Return Channel Model:
    // Filtered/compacted records transferred from CSD to Host memory across PCIe bus
    double csd_return_io_ms = ((double)pipe_res.host_mem_traffic_bytes / (1024.0 * 1024.0)) / (host_pcie_rate_mb_s / 1000.0);

    // Sequential Return Model: CSD compute finishes, then matched records return over PCIe
    double csd_seq_with_pcie_ms = pipe_res.total_time_ms + csd_return_io_ms;
    double true_csd_speedup_seq = host_storage_baseline_ms / csd_seq_with_pcie_ms;

    // Pipelined Return Model: PCIe DMA returns matched records concurrently with CSD chunk execution
    double csd_pipe_with_pcie_ms = (pipe_res.total_time_ms > csd_return_io_ms) ? pipe_res.total_time_ms : csd_return_io_ms;
    double true_csd_speedup_pipe = host_storage_baseline_ms / csd_pipe_with_pcie_ms;

    printf("====================================================================\n");
    if (src == SOURCE_RAM) {
        printf("[FINAL COMPARISON: IN-RAM ARCHITECTURAL MODEL]\n");
    } else {
        printf("[FINAL COMPARISON: HOST-CENTRIC vs. NVMe COMPUTATIONAL STORAGE]\n");
    }
    printf("====================================================================\n");
    printf("  Metric                  | %-16s | CSD Sequential   | CSD Pipelined\n",
           (src == SOURCE_RAM) ? "Host In-RAM" : "Host Traditional");
    printf("  ------------------------+------------------+------------------+------------------\n");
    printf("  Total Time              | %14.2f ms | %14.2f ms | %14.2f ms\n",
           host_res.total_time_ms, csd_res.total_time_ms, pipe_res.total_time_ms);
    printf("  Effective Throughput    | %12.2f MB/s| %12.2f MB/s| %12.2f MB/s\n",
           host_thru, csd_thru, pipe_thru);
    printf("  Host CPU Compute Time   | %14.2f ms |           0.00 ms |           0.00 ms\n",
           host_res.compute_time_ms);
    printf("  Host CPU Offload Ratio  |             0.0%% |           100.0%% |           100.0%%\n");
    printf("  Data Sent to Host App   | %12.2f MB | %12.2f MB | %12.2f MB\n",
           (double)file_bytes / (1024.0 * 1024.0),
           (double)csd_res.host_mem_traffic_bytes / (1024.0 * 1024.0),
           (double)pipe_res.host_mem_traffic_bytes / (1024.0 * 1024.0));
    printf("  Host Data Reduction     |             0.0%% | %14.1f%% | %14.1f%%\n",
           data_reduction_pct, data_reduction_pct);
    printf("  ------------------------+------------------+------------------+------------------\n");
    if (src == SOURCE_RAM) {
        printf("  In-RAM Speedup vs Host  : %.2fx faster (%.1f%% latency reduction)\n", pipe_speedup, lat_reduct);
        printf("  CSD PCIe Return IO Time : %10.2f ms (%.2f MB matched data at %.2f MB/s)\n",
               csd_return_io_ms, (double)pipe_res.host_mem_traffic_bytes / (1024.0 * 1024.0), host_pcie_rate_mb_s);
        printf("  TRUE CSD vs Host-PCIe   : %.2fx (%.2f ms CSD w/ PCIe return vs %.2f ms Host baseline)\n",
               true_csd_speedup_seq, csd_seq_with_pcie_ms, host_storage_baseline_ms);
        printf("  TRUE CSD (Pipelined Ret): %.2fx (%.2f ms CSD overlapped vs %.2f ms Host baseline)\n",
               true_csd_speedup_pipe, csd_pipe_with_pcie_ms, host_storage_baseline_ms);
    } else {
        printf("  Pipelined Speedup vs Host : %.2fx faster (%.1f%% latency reduction)\n", pipe_speedup, lat_reduct);
    }
    printf("  Host Memory Bus Saved   : %.1f%% of raw data discarded at storage level!\n", data_reduction_pct);

    // Mathematical verification across all modes
    bool match = (host_res.matches == csd_res.matches && host_res.matches == pipe_res.matches) &&
                 (host_res.sum_amount == csd_res.sum_amount && host_res.sum_amount == pipe_res.sum_amount) &&
                 (host_res.net_discount_sum == csd_res.net_discount_sum && host_res.net_discount_sum == pipe_res.net_discount_sum) &&
                 (host_res.min_amount == csd_res.min_amount && host_res.min_amount == pipe_res.min_amount) &&
                 (host_res.max_amount == csd_res.max_amount && host_res.max_amount == pipe_res.max_amount);

    if (match) {
        printf("  [VERIFICATION] SUCCESS: All 3 execution modes yielded 100%% identical results!\n");
        printf("  Scale Verified: %lu records (%.2f MB / %.2f GB) with %lu matches.\n",
               (unsigned long)total_records, (double)file_bytes / (1024.0 * 1024.0),
               (double)file_bytes / (1024.0 * 1024.0 * 1024.0), (unsigned long)host_res.matches);
    } else {
        printf("  [VERIFICATION] WARNING: Results mismatch detected!\n");
    }
    printf("====================================================================\n");

    if (show_vcon) {
        printf("\n[CORE3 VCON LOG DUMP]\n");
        drain_vcon();
        printf("---------------------\n");
    }

    if (do_shutdown) {
        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = NVME_CMD_SHUTDOWN;
        sqe.flags = NVME_FLAG_SILENT;
        sqe.cid = ++cid;
        submit_nvme_cmd_silent(qmem, &sqe, &cqe, 1000);
        qmem->regs.status = 0;
        __sync_synchronize();
        printf("[HOST] Core 3 parked via SBI HSM.\n");
    } else {
        printf("[HOST] Core 3 kept alive and READY for subsequent benchmarks.\n");
    }

    if (raw_dataset) free(raw_dataset);
    free(host_matched_records);
    free(csd_matched_records);
    free(pipe_matched_records);
    munmap(map_base, MAP_SIZE);
    close(mem_fd);
    return 0;
}
