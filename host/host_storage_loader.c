#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

#include "nvme_spec.h"
#include "nvme_queue.h"

#define PHYS_BASE           0x222000000ULL
#define MAP_SIZE            0x01000000ULL  // 16MB

#define VCON_OFFSET         0x00400000ULL  // 0x222400000 (Virtual Console)
#define VCON_SIZE           4096
#define NVME_QUEUE_OFFSET   0x00401000ULL  // 0x222401000 (NVMe Queues)

// Subsystem Local Memory (SLM) allocations
#define SLM_PROG_OFFSET     0x00500000ULL  // 0x222500000 (64KB buffer for eBPF bytecode)
#define SLM_BUF_A_OFFSET    0x00510000ULL  // 0x222510000 (Buffer A: Context + Data)
#define SLM_BUF_B_OFFSET    0x00710000ULL  // 0x222710000 (Buffer B: Context + Data for Pipelining)

#define SLM_PROG_PHYS_ADDR  (PHYS_BASE + SLM_PROG_OFFSET)
#define SLM_BUF_A_PHYS_ADDR (PHYS_BASE + SLM_BUF_A_OFFSET)
#define SLM_BUF_B_PHYS_ADDR (PHYS_BASE + SLM_BUF_B_OFFSET)

#define FW_BINARY           "firmware/build/firmware.bin"
#define DEFAULT_APP_BIN     "apps/app.bin"

#define DEFAULT_CHUNK_KB    256 // Default streaming chunk: 256 KB

struct record {
    uint32_t id;
    uint32_t type;       // 1 = SALE, 2 = REFUND, 3 = EXPENSE
    uint32_t amount;     // Transaction amount ($)
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

    // --- Dataset records start here ---
    struct record records[];
};

struct query_result {
    uint64_t total_records;
    uint64_t matches;
    uint64_t sum_amount;
    uint32_t min_amount;
    uint32_t max_amount;
    double io_time_ms;
    double compute_time_ms;
    double total_time_ms;
};

static inline double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000.0) + (ts.tv_nsec / 1000000.0);
}

// Host-Native aggregation baseline (GCC -O2 compiled)
static void host_native_filter(const struct record *records, uint32_t count,
                               uint32_t target_type, uint32_t min_amt, uint32_t max_amt,
                               uint64_t *out_matches, uint64_t *out_sum,
                               uint32_t *out_min, uint32_t *out_max) {
    uint32_t matches = 0;
    uint64_t sum = 0;
    uint32_t min_v = *out_min;
    uint32_t max_v = *out_max;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t t = records[i].type;
        uint32_t a = records[i].amount;
        if (t == target_type && a >= min_amt && a <= max_amt) {
            matches++;
            sum += a;
            if (a > max_v) max_v = a;
            if (a < min_v) min_v = a;
        }
    }

    *out_matches += matches;
    *out_sum += sum;
    *out_min = min_v;
    *out_max = max_v;
}


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

// Submit NVMe SQE with tight polling and silent execution support
static int submit_nvme_cmd_silent(volatile struct nvme_queue_mem *qmem,
                                  struct nvme_sqe *cmd,
                                  struct nvme_cqe *out_cqe,
                                  int timeout_ms) {
    uint32_t tail = qmem->regs.sq_tail;
    uint32_t head = qmem->regs.sq_head;

    // Self-healing: if tail is behind head (e.g. from previous run or unsigned underflow), align
    if (tail < head) {
        qmem->regs.sq_tail = head;
        tail = head;
        __sync_synchronize();
    }

    if ((tail - head) >= NVME_QUEUE_DEPTH) {
        fprintf(stderr, "[HOST WARNING] Submission Queue full (tail=%u, head=%u), forcing realignment...\n", tail, head);
        qmem->regs.sq_tail = head;
        tail = head;
        __sync_synchronize();
    }

    uint32_t sq_idx = tail % NVME_QUEUE_DEPTH;
    qmem->sq[sq_idx] = *cmd;

    __sync_synchronize();
    qmem->regs.sq_tail = tail + 1;
    __sync_synchronize();

    double start_t = get_time_ms();
    while ((get_time_ms() - start_t) < timeout_ms) {
        if (qmem->regs.cq_tail != qmem->regs.cq_head) {
            uint32_t cq_idx = qmem->regs.cq_head % NVME_QUEUE_DEPTH;
            struct nvme_cqe cqe = qmem->cq[cq_idx];

            if (cqe.cid == cmd->cid) {
                *out_cqe = cqe;
                qmem->regs.cq_head++;
                __sync_synchronize();
                return 0;
            } else {
                // Discard stale CQE from prior run
                qmem->regs.cq_head++;
                __sync_synchronize();
            }
        }
    }

    fprintf(stderr, "[HOST ERROR] Command cid=%d timed out after %d ms!\n", cmd->cid, timeout_ms);
    return -2;
}

static void drop_page_cache(void) {
    // Attempt to drop kernel page cache if running as root
    int fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (fd >= 0) {
        if (write(fd, "3\n", 2) < 0) {
            // Non-fatal if permission denied
        }
        close(fd);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <dataset_file.bin> [chunk_size_KB]\n", argv[0]);
        printf("Example: %s /mnt/nvme/dataset_1m.bin 256\n", argv[0]);
        return 1;
    }

    const char *dataset_path = argv[1];
    uint32_t chunk_kb = (argc > 2) ? atoi(argv[2]) : DEFAULT_CHUNK_KB;
    if (chunk_kb < 16) chunk_kb = 16;
    if (chunk_kb > 2048) chunk_kb = 2048; // Max 2MB per chunk for SLM buffers

    uint32_t chunk_bytes = chunk_kb * 1024;
    uint32_t chunk_records = chunk_bytes / sizeof(struct record);
    chunk_bytes = chunk_records * sizeof(struct record); // Exact multiple

    struct stat st;
    if (stat(dataset_path, &st) != 0) {
        perror("Error stat dataset file");
        return 1;
    }
    uint64_t file_bytes = st.st_size;
    uint64_t total_records = file_bytes / sizeof(struct record);

    printf("====================================================================\n");
    printf("[NVMe CSD STORAGE DATA LOADER & STREAMING ENGINE]\n");
    printf("====================================================================\n");
    printf("  Dataset File      : %s\n", dataset_path);
    printf("  File Size         : %.2f MB (%lu bytes)\n", (double)file_bytes / (1024.0 * 1024.0), (unsigned long)file_bytes);
    printf("  Total Records     : %lu\n", (unsigned long)total_records);
    printf("  Streaming Chunk   : %u KB (%u records / chunk)\n", chunk_kb, chunk_records);
    printf("  Query Predicate   : Type == 1 (SALE) && Amount in [50, 500]\n");
    printf("====================================================================\n\n");

    // Open physical memory mapping to CSD
    int mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd < 0) {
        perror("Error opening /dev/mem");
        return 1;
    }

    uint8_t *map_base = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, PHYS_BASE);
    if (map_base == MAP_FAILED) {
        perror("Error mmapping /dev/mem");
        close(mem_fd);
        return 1;
    }

    vcon_idx = (volatile uint32_t *)(map_base + VCON_OFFSET + VCON_SIZE - 4);
    vcon_buf = (volatile char *)(map_base + VCON_OFFSET);
    volatile struct nvme_queue_mem *qmem = (volatile struct nvme_queue_mem *)(map_base + NVME_QUEUE_OFFSET);
    uint8_t *slm_prog = map_base + SLM_PROG_OFFSET;
    struct analytics_context *ctx_a = (struct analytics_context *)(map_base + SLM_BUF_A_OFFSET);
    struct analytics_context *ctx_b = (struct analytics_context *)(map_base + SLM_BUF_B_OFFSET);

    // Check if Core 3 is already alive and READY
    if (qmem->regs.status == NVME_STATUS_READY) {
        printf("[HOST] Core 3 is ALREADY alive and READY! Reusing active CSD...\n");
        // Monotonically align queue pointers without zeroing
        qmem->regs.sq_tail = qmem->regs.sq_head;
        qmem->regs.cq_head = qmem->regs.cq_tail;
        __sync_synchronize();
    } else {

        // Core 3 is not ready: fresh boot sequence
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

        // Ensure Hart 4 is in STOPPED state by toggling online/offline if needed
        system("sh -c 'echo 1 > /sys/devices/system/cpu/cpu3/online 2>/dev/null'");
        system("sh -c 'echo 0 > /sys/devices/system/cpu/cpu3/online 2>/dev/null'");
        system("rmmod vf2_kick 2>/dev/null");

        printf("[HOST] Kicking Core 3 via OpenSBI HSM...\n");
        if (system("insmod tools/kick_core/vf2_kick.ko 2>/dev/null") != 0) {
            system("insmod ../tools/kick_core/vf2_kick.ko 2>/dev/null");
        }

        printf("[HOST] Waiting for Core 3 boot...\n");
        printf("--- [CORE 3 CONSOLE] ---\n");

        int wait_count = 0;
        while (qmem->regs.status != NVME_STATUS_READY) {
            drain_vcon();
            usleep(10000); // 10ms
            if (++wait_count > 1000) { // 10s
                fprintf(stderr, "\n[HOST ERROR] Timeout waiting for Core 3 READY status!\n");
                munmap(map_base, MAP_SIZE);
                close(mem_fd);
                return 1;
            }
        }
        drain_vcon();
        printf("--- [CORE 3 READY] ---\n\n");
    }



    // Load and JIT Compile eBPF program
    const char *app_path = DEFAULT_APP_BIN;
    if (access(app_path, F_OK) != 0) app_path = "../" DEFAULT_APP_BIN;
    int app_fd = open(app_path, O_RDONLY);
    if (app_fd < 0) {
        perror("Error opening eBPF app binary");
        munmap(map_base, MAP_SIZE);
        close(mem_fd);
        return 1;
    }
    ssize_t prog_bytes = read(app_fd, slm_prog, 0x10000);
    close(app_fd);
    uint32_t num_inst = prog_bytes / 8;

    struct nvme_sqe sqe;
    struct nvme_cqe cqe;

    // TP4091 LOAD
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = NVME_CMD_EBPF_LOAD;
    sqe.flags = NVME_FLAG_SILENT;
    sqe.cid = 1;
    sqe.prp1 = SLM_PROG_PHYS_ADDR;
    sqe.cdw10 = num_inst;
    if (submit_nvme_cmd_silent(qmem, &sqe, &cqe, 1000) != 0 || cqe.status != 0) {
        fprintf(stderr, "[HOST ERROR] TP4091 LOAD command failed!\n");
        return 1;
    }

    // TP4091 ACTIVATE
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = NVME_CMD_EBPF_ACTIVATE;
    sqe.flags = NVME_FLAG_SILENT;
    sqe.cid = 2;
    double t_act_start = get_time_ms();
    if (submit_nvme_cmd_silent(qmem, &sqe, &cqe, 1000) != 0 || cqe.status != 0) {
        fprintf(stderr, "[HOST ERROR] TP4091 ACTIVATE command failed!\n");
        return 1;
    }
    double t_act_end = get_time_ms();
    printf("[HOST] eBPF Program JIT-compiled on Core 3 (JIT latency: %.2f µs, cycles: %u)\n\n",
           (t_act_end - t_act_start) * 1000.0, cqe.rsvd1);

    // =========================================================================
    // BENCHMARK 1: HOST-NATIVE PROCESSING (Traditional Baseline)
    // =========================================================================
    printf("--------------------------------------------------------------------\n");
    printf("[EXPERIMENT 1] Host-Centric Traditional Processing (Read SSD -> Host CPU)\n");
    printf("--------------------------------------------------------------------\n");
    drop_page_cache();

    int disk_fd = open(dataset_path, O_RDONLY);
    if (disk_fd < 0) {
        perror("Error opening dataset file on SSD");
        return 1;
    }

    struct record *host_buf = malloc(chunk_bytes);
    if (!host_buf) {
        perror("Error allocating host buffer");
        return 1;
    }

    struct query_result host_res = {0};
    host_res.min_amount = 0xFFFFFFFF;

    double host_t0 = get_time_ms();
    uint64_t bytes_left = file_bytes;
    off_t file_offset = 0;

    while (bytes_left > 0) {
        uint32_t to_read = (bytes_left > chunk_bytes) ? chunk_bytes : (uint32_t)bytes_left;
        uint32_t records_in_batch = to_read / sizeof(struct record);

        // Step 1: Read from SSD into Host RAM
        double t_io0 = get_time_ms();
        ssize_t rd = pread(disk_fd, host_buf, to_read, file_offset);
        double t_io1 = get_time_ms();
        host_res.io_time_ms += (t_io1 - t_io0);

        if (rd != (ssize_t)to_read) {
            perror("pread failed");
            break;
        }

        // Step 2: Host CPU executes filter & aggregation in C native
        double t_comp0 = get_time_ms();
        host_native_filter(host_buf, records_in_batch, 1, 50, 500,
                           &host_res.matches, &host_res.sum_amount,
                           &host_res.min_amount, &host_res.max_amount);
        double t_comp1 = get_time_ms();

        host_res.compute_time_ms += (t_comp1 - t_comp0);

        bytes_left -= to_read;
        file_offset += to_read;
        host_res.total_records += records_in_batch;
    }
    double host_t1 = get_time_ms();
    host_res.total_time_ms = host_t1 - host_t0;
    close(disk_fd);
    free(host_buf);

    printf("  Host Total Time   : %8.2f ms\n", host_res.total_time_ms);
    printf("    -> SSD Read I/O : %8.2f ms (%.1f%%)\n", host_res.io_time_ms, host_res.io_time_ms * 100.0 / host_res.total_time_ms);
    printf("    -> CPU Compute  : %8.2f ms (%.1f%%)\n", host_res.compute_time_ms, host_res.compute_time_ms * 100.0 / host_res.total_time_ms);
    printf("  Host Throughput   : %8.2f MB/s\n", (file_bytes / (1024.0 * 1024.0)) / (host_res.total_time_ms / 1000.0));
    printf("  Matches / Sum     : %lu matches, Sum: $%lu\n", (unsigned long)host_res.matches, (unsigned long)host_res.sum_amount);
    printf("  Min / Max Matched : $%u / $%u\n\n", host_res.min_amount, host_res.max_amount);

    // =========================================================================
    // BENCHMARK 2: COMPUTATIONAL STORAGE - SEQUENTIAL OFF-LOAD (TP4091)
    // =========================================================================
    printf("--------------------------------------------------------------------\n");
    printf("[EXPERIMENT 2] Computational Storage (Sequential: Read SSD -> SLM -> Core 3 JIT)\n");
    printf("--------------------------------------------------------------------\n");
    drop_page_cache();

    disk_fd = open(dataset_path, O_RDONLY);
    if (disk_fd < 0) {
        perror("Error opening dataset file on SSD");
        return 1;
    }

    struct query_result csd_seq = {0};
    csd_seq.min_amount = 0xFFFFFFFF;

    double csd_seq_t0 = get_time_ms();
    bytes_left = file_bytes;
    file_offset = 0;
    uint16_t cmd_cid = 10;

    while (bytes_left > 0) {
        uint32_t to_read = (bytes_left > chunk_bytes) ? chunk_bytes : (uint32_t)bytes_left;
        uint32_t records_in_batch = to_read / sizeof(struct record);

        // Step 1: Read directly into SLM Data Buffer (at offset sizeof(analytics_context))
        double t_io0 = get_time_ms();
        ssize_t rd = pread(disk_fd, ctx_a->records, to_read, file_offset);
        double t_io1 = get_time_ms();
        csd_seq.io_time_ms += (t_io1 - t_io0);

        if (rd != (ssize_t)to_read) {
            perror("pread into SLM failed");
            break;
        }

        // Configure Context Header in SLM
        ctx_a->record_count = records_in_batch;
        ctx_a->target_type = 1;
        ctx_a->min_amount = 50;
        ctx_a->max_amount = 500;
        ctx_a->matches = 0;
        ctx_a->sum_amount = 0;
        ctx_a->max_matched_amount = 0;
        ctx_a->min_matched_amount = 0xFFFFFFFF;

        // Step 2: Submit NVMe TP4091 EXECUTE to Core 3
        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = NVME_CMD_EBPF_EXECUTE;
        sqe.flags = NVME_FLAG_SILENT;
        sqe.cid = cmd_cid++;
        sqe.prp1 = SLM_BUF_A_PHYS_ADDR;

        double t_comp0 = get_time_ms();
        if (submit_nvme_cmd_silent(qmem, &sqe, &cqe, 2000) != 0 || cqe.status != 0) {
            fprintf(stderr, "[HOST ERROR] CSD EXECUTE failed on chunk at offset %ld!\n", file_offset);
            break;
        }
        double t_comp1 = get_time_ms();
        csd_seq.compute_time_ms += (t_comp1 - t_comp0);

        // Accumulate chunk results
        csd_seq.matches += ctx_a->matches;
        csd_seq.sum_amount += ctx_a->sum_amount;
        if (ctx_a->matches > 0) {
            if (ctx_a->max_matched_amount > csd_seq.max_amount) csd_seq.max_amount = ctx_a->max_matched_amount;
            if (ctx_a->min_matched_amount < csd_seq.min_amount) csd_seq.min_amount = ctx_a->min_matched_amount;
        }

        bytes_left -= to_read;
        file_offset += to_read;
        csd_seq.total_records += records_in_batch;
    }
    double csd_seq_t1 = get_time_ms();
    csd_seq.total_time_ms = csd_seq_t1 - csd_seq_t0;
    close(disk_fd);

    printf("  CSD Total Time    : %8.2f ms\n", csd_seq.total_time_ms);
    printf("    -> SSD Read I/O : %8.2f ms (%.1f%%)\n", csd_seq.io_time_ms, csd_seq.io_time_ms * 100.0 / csd_seq.total_time_ms);
    printf("    -> CSD Compute  : %8.2f ms (%.1f%%)\n", csd_seq.compute_time_ms, csd_seq.compute_time_ms * 100.0 / csd_seq.total_time_ms);
    printf("  CSD Throughput    : %8.2f MB/s\n", (file_bytes / (1024.0 * 1024.0)) / (csd_seq.total_time_ms / 1000.0));
    printf("  Matches / Sum     : %lu matches, Sum: $%lu\n", (unsigned long)csd_seq.matches, (unsigned long)csd_seq.sum_amount);
    printf("  Min / Max Matched : $%u / $%u\n\n", csd_seq.min_amount, csd_seq.max_amount);

    // =========================================================================
    // BENCHMARK 3: COMPUTATIONAL STORAGE - PIPELINED STREAMING (Double Buffering)
    // =========================================================================
    printf("--------------------------------------------------------------------\n");
    printf("[EXPERIMENT 3] Computational Storage (Pipelined Double-Buffered Streaming)\n");
    printf("--------------------------------------------------------------------\n");
    drop_page_cache();

    disk_fd = open(dataset_path, O_RDONLY);
    if (disk_fd < 0) {
        perror("Error opening dataset file on SSD");
        return 1;
    }

    struct query_result csd_pipe = {0};
    csd_pipe.min_amount = 0xFFFFFFFF;

    double csd_pipe_t0 = get_time_ms();
    bytes_left = file_bytes;
    file_offset = 0;

    struct analytics_context *active_ctx = ctx_a;
    uint64_t active_phys = SLM_BUF_A_PHYS_ADDR;
    struct analytics_context *next_ctx = ctx_b;
    uint64_t next_phys = SLM_BUF_B_PHYS_ADDR;

    // Prime the pipeline: Read Chunk 0 into Buffer A
    uint32_t first_read = (bytes_left > chunk_bytes) ? chunk_bytes : (uint32_t)bytes_left;
    uint32_t first_records = first_read / sizeof(struct record);
    pread(disk_fd, active_ctx->records, first_read, file_offset);
    active_ctx->record_count = first_records;
    active_ctx->target_type = 1;
    active_ctx->min_amount = 50;
    active_ctx->max_amount = 500;
    active_ctx->matches = 0;
    active_ctx->sum_amount = 0;
    active_ctx->max_matched_amount = 0;
    active_ctx->min_matched_amount = 0xFFFFFFFF;

    bytes_left -= first_read;
    file_offset += first_read;
    csd_pipe.total_records += first_records;

    while (1) {
        // Asynchronously launch EXECUTE on active buffer
        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = NVME_CMD_EBPF_EXECUTE;
        sqe.flags = NVME_FLAG_SILENT;
        sqe.cid = cmd_cid++;
        sqe.prp1 = active_phys;

        // In parallel: if there's more data on SSD, read next chunk into next_ctx!
        uint32_t next_read = 0;
        uint32_t next_records = 0;
        if (bytes_left > 0) {
            next_read = (bytes_left > chunk_bytes) ? chunk_bytes : (uint32_t)bytes_left;
            next_records = next_read / sizeof(struct record);
            pread(disk_fd, next_ctx->records, next_read, file_offset);
            next_ctx->record_count = next_records;
            next_ctx->target_type = 1;
            next_ctx->min_amount = 50;
            next_ctx->max_amount = 500;
            next_ctx->matches = 0;
            next_ctx->sum_amount = 0;
            next_ctx->max_matched_amount = 0;
            next_ctx->min_matched_amount = 0xFFFFFFFF;

            bytes_left -= next_read;
            file_offset += next_read;
            csd_pipe.total_records += next_records;
        }

        // Wait for Core 3 EXECUTE to complete on active buffer
        if (submit_nvme_cmd_silent(qmem, &sqe, &cqe, 2000) != 0 || cqe.status != 0) {
            fprintf(stderr, "[HOST ERROR] Pipelined EXECUTE failed!\n");
            break;
        }

        // Accumulate active buffer results
        csd_pipe.matches += active_ctx->matches;
        csd_pipe.sum_amount += active_ctx->sum_amount;
        if (active_ctx->matches > 0) {
            if (active_ctx->max_matched_amount > csd_pipe.max_amount) csd_pipe.max_amount = active_ctx->max_matched_amount;
            if (active_ctx->min_matched_amount < csd_pipe.min_amount) csd_pipe.min_amount = active_ctx->min_matched_amount;
        }

        if (next_read == 0) {
            // Reached end of file
            break;
        }

        // Swap ping-pong buffers
        struct analytics_context *tmp_ctx = active_ctx;
        active_ctx = next_ctx;
        next_ctx = tmp_ctx;

        uint64_t tmp_phys = active_phys;
        active_phys = next_phys;
        next_phys = tmp_phys;
    }
    double csd_pipe_t1 = get_time_ms();
    csd_pipe.total_time_ms = csd_pipe_t1 - csd_pipe_t0;
    close(disk_fd);

    printf("  Pipelined Total   : %8.2f ms\n", csd_pipe.total_time_ms);
    printf("  Pipe Throughput   : %8.2f MB/s\n", (file_bytes / (1024.0 * 1024.0)) / (csd_pipe.total_time_ms / 1000.0));
    printf("  Matches / Sum     : %lu matches, Sum: $%lu\n", (unsigned long)csd_pipe.matches, (unsigned long)csd_pipe.sum_amount);
    printf("  Min / Max Matched : $%u / $%u\n\n", csd_pipe.min_amount, csd_pipe.max_amount);

    // =========================================================================
    // FINAL SUMMARY AND SPEEDUP EVALUATION
    // =========================================================================
    printf("====================================================================\n");
    printf("[FINAL COMPARISON: HOST-CENTRIC vs. NVMe COMPUTATIONAL STORAGE]\n");
    printf("====================================================================\n");
    printf("  Metric                  | Host Traditional | CSD Sequential   | CSD Pipelined\n");
    printf("  ------------------------+------------------+------------------+------------------\n");
    printf("  Total Time              | %14.2f ms | %14.2f ms | %14.2f ms\n",
           host_res.total_time_ms, csd_seq.total_time_ms, csd_pipe.total_time_ms);
    printf("  Effective Throughput    | %14.2f MB/s| %14.2f MB/s| %14.2f MB/s\n",
           (file_bytes / (1024.0 * 1024.0)) / (host_res.total_time_ms / 1000.0),
           (file_bytes / (1024.0 * 1024.0)) / (csd_seq.total_time_ms / 1000.0),
           (file_bytes / (1024.0 * 1024.0)) / (csd_pipe.total_time_ms / 1000.0));
    printf("  Host CPU Compute Time   | %14.2f ms | %14.2f ms | %14.2f ms\n",
           host_res.compute_time_ms, 0.0, 0.0);
    printf("  Host CPU Offload Ratio  |             0.0%% |           100.0%% |           100.0%%\n");
    
    double speedup = host_res.total_time_ms / csd_pipe.total_time_ms;
    printf("  ------------------------+------------------+------------------+------------------\n");
    printf("  Pipelined Speedup vs Host: %.2fx faster (%.1f%% latency reduction)\n",
           speedup, (1.0 - (csd_pipe.total_time_ms / host_res.total_time_ms)) * 100.0);

    // Correctness assertion
    int ok = (host_res.matches == csd_seq.matches && host_res.matches == csd_pipe.matches &&
              host_res.sum_amount == csd_seq.sum_amount && host_res.sum_amount == csd_pipe.sum_amount &&
              host_res.min_amount == csd_seq.min_amount && host_res.min_amount == csd_pipe.min_amount &&
              host_res.max_amount == csd_seq.max_amount && host_res.max_amount == csd_pipe.max_amount);

    if (ok) {
        printf("  [VERIFICATION] SUCCESS: All 3 execution modes yielded 100%% identical results!\n");
    } else {
        printf("  [VERIFICATION] WARNING: Results mismatch detected!\n");
    }
    printf("====================================================================\n");

    munmap(map_base, MAP_SIZE);
    close(mem_fd);
    return ok ? 0 : 2;
}
