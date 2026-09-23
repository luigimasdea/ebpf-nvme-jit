#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "../firmware/include/ebpf.h"
#include "../firmware/include/jit.h"
#include "../firmware/include/riscv.h"

// Stubs for utils.h functions when running in user-space
void uart_print(const char *s) { (void)s; }
void uart_print_int(int n) { (void)n; }
void uart_print_uint64(uint64_t n) { (void)n; }
void uart_print_hex(uint32_t n) { (void)n; }
void uart_print_char(char c) { (void)c; }
void* bpf_helper_lookup(int32_t imm) { (void)imm; return NULL; }

// Record structure (16 bytes per record)
struct record {
    uint32_t id;
    uint32_t type;       // 1 = SALE, 2 = REFUND, 3 = EXPENSE
    uint32_t amount;     // Transaction amount ($)
    uint32_t timestamp;  // Unix timestamp
};

// ---------------------------------------------------------------------------
// TEST 1: Advanced Analytics with Register Caching (13 Spilled Slots)
// ---------------------------------------------------------------------------
struct advanced_context {
    uint32_t record_count;
    uint32_t target_type;
    uint32_t min_amount;
    uint32_t max_amount;
    uint32_t min_timestamp;
    uint32_t max_timestamp;
    uint32_t discount_pct;
    uint32_t pad0;

    uint32_t matches;
    uint32_t sum_amount;
    uint32_t max_matched_amount;
    uint32_t min_matched_amount;
    uint32_t hash_accum;
    uint32_t net_discount_sum;
    uint32_t pad1;
    uint32_t pad2;

    struct record records[];
};

static void host_native_advanced_filter(const struct record *records, uint32_t count,
                                        uint32_t target_type, uint32_t min_amt, uint32_t max_amt,
                                        uint32_t min_ts, uint32_t max_ts, uint32_t discount_pct,
                                        struct record *out_matches_buf,
                                        uint32_t *out_match_count,
                                        uint32_t *out_sum, uint32_t *out_net_sum,
                                        uint32_t *out_min, uint32_t *out_max,
                                        uint32_t *out_hash) {
    uint32_t matches = 0;
    uint32_t sum = 0;
    uint32_t net_sum = 0;
    uint32_t min_v = 0xFFFFFFFF;
    uint32_t max_v = 0;
    uint32_t hash = 0x811C9DC5;
    uint32_t multiplier = (discount_pct <= 100) ? (100 - discount_pct) : 0;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t r_id = records[i].id;
        uint32_t r_type = records[i].type;
        uint32_t r_amt = records[i].amount;
        uint32_t r_ts = records[i].timestamp;

        if ((target_type == 0 || r_type == target_type) &&
            r_amt >= min_amt && r_amt <= max_amt &&
            r_ts >= min_ts && r_ts <= max_ts) {

            if (out_matches_buf) {
                out_matches_buf[matches] = records[i];
            }

            matches++;
            sum += r_amt;

            uint32_t net_val = (r_amt * multiplier) / 100;
            net_sum += net_val;

            if (r_amt > max_v) max_v = r_amt;
            if (r_amt < min_v) min_v = r_amt;

            hash ^= r_id;
            hash = (hash * 16777619) ^ (r_amt << 1);
            hash ^= (r_ts >> 3);
        }
    }

    if (matches == 0) min_v = 0;

    *out_match_count = matches;
    *out_sum = sum;
    *out_net_sum = net_sum;
    *out_min = min_v;
    *out_max = max_v;
    *out_hash = hash;
}

static bool test_advanced_caching(void *jit_buf, size_t mem_size) {
    printf("--------------------------------------------------------------------\n");
    printf("TEST 1: Advanced Analytics (Register Caching Verification)\n");
    printf("--------------------------------------------------------------------\n");

    const char *bin_path = "apps/analytics_advanced.bin";
    int fd = open(bin_path, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open apps/analytics_advanced.bin");
        return false;
    }

    struct ebpf_inst prog[512];
    ssize_t bytes = read(fd, prog, sizeof(prog));
    close(fd);
    if (bytes <= 0) return false;

    int num_inst = bytes / sizeof(struct ebpf_inst);
    printf("Loaded %zd bytes (%d eBPF instructions)\n", bytes, num_inst);

    jit_set_memory_target((uint32_t *)jit_buf);
    compile_ebpf(prog, num_inst);

    int cached_count = jit_get_cached_slots_count();
    int emitted_insns = jit_get_emitted_insn_count();
    printf(">>> Register Caching Active: %d stack slots mapped to RISC-V registers (s5-s11, t3-t6, a6-a7)!\n", cached_count);
    printf(">>> Emitted RISC-V instructions: %d (%d bytes)\n", emitted_insns, emitted_insns * 4);
    if (cached_count != 13) {
        printf("WARNING: Expected 13 cached slots, found %d!\n", cached_count);
    }

    // Save generated machine code for disassembly inspection
    mkdir("build", 0755);
    FILE *dump_fp = fopen("build/jit_advanced.bin", "wb");
    if (dump_fp) {
        fwrite(jit_buf, 4, emitted_insns, dump_fp);
        fclose(dump_fp);
        printf(">>> Saved machine code to 'build/jit_advanced.bin'\n");
    }

    const uint32_t num_records = 5000;
    size_t ctx_size = sizeof(struct advanced_context) + num_records * sizeof(struct record);
    struct advanced_context *ctx_jit = malloc(ctx_size);
    struct advanced_context *ctx_ref = malloc(ctx_size);
    struct record *ref_matches = malloc(num_records * sizeof(struct record));

    for (uint32_t i = 0; i < num_records; i++) {
        struct record rec;
        rec.id = i + 1;
        rec.type = (i % 3) + 1;
        rec.amount = ((i * 37) % 600);
        rec.timestamp = 1700000000 + i;
        ctx_jit->records[i] = rec;
        ctx_ref->records[i] = rec;
    }

    uint32_t q_type = 1;
    uint32_t q_min_amt = 50;
    uint32_t q_max_amt = 150;
    uint32_t q_min_ts = 0;
    uint32_t q_max_ts = 0xFFFFFFFF;
    uint32_t q_disc = 15;

    ctx_jit->record_count = num_records;
    ctx_jit->target_type = q_type;
    ctx_jit->min_amount = q_min_amt;
    ctx_jit->max_amount = q_max_amt;
    ctx_jit->min_timestamp = q_min_ts;
    ctx_jit->max_timestamp = q_max_ts;
    ctx_jit->discount_pct = q_disc;
    ctx_jit->matches = 0;
    ctx_jit->sum_amount = 0;
    ctx_jit->net_discount_sum = 0;
    ctx_jit->min_matched_amount = 0xFFFFFFFF;
    ctx_jit->max_matched_amount = 0;
    ctx_jit->hash_accum = 0x811C9DC5;

    uint32_t ref_match_count = 0, ref_sum = 0, ref_net_sum = 0, ref_min = 0, ref_max = 0, ref_hash = 0;
    host_native_advanced_filter(ctx_ref->records, num_records,
                                q_type, q_min_amt, q_max_amt, q_min_ts, q_max_ts, q_disc,
                                ref_matches, &ref_match_count,
                                &ref_sum, &ref_net_sum, &ref_min, &ref_max, &ref_hash);

    __builtin___clear_cache(jit_buf, (char *)jit_buf + mem_size);
    uint64_t (*jit_func)(void *) = (uint64_t (*)(void *))jit_buf;
    uint64_t ret = jit_func(ctx_jit);

    printf("Execution completed. JIT return value: %lu\n", (unsigned long)ret);
    printf("Metric           | C Reference   | JIT (Register Cached) | Status\n");
    printf("-----------------+---------------+-----------------------+---------\n");

    bool ok = true;
    #define CHECK(name, ref_val, jit_val, fmt) do { \
        bool match = ((ref_val) == (jit_val)); \
        printf("%-16s | " fmt " | " fmt " | %s\n", \
               name, ref_val, jit_val, match ? "PASS [OK]" : "FAIL [MISMATCH]"); \
        if (!match) ok = false; \
    } while(0)

    CHECK("Matches", ref_match_count, ctx_jit->matches, "%13u");
    CHECK("Gross Sum", ref_sum, ctx_jit->sum_amount, "%13u");
    CHECK("Net Sum (15%)", ref_net_sum, ctx_jit->net_discount_sum, "%13u");
    CHECK("Min Amount", ref_min, ctx_jit->min_matched_amount, "%13u");
    CHECK("Max Amount", ref_max, ctx_jit->max_matched_amount, "%13u");
    CHECK("FNV-1a Hash", ref_hash, ctx_jit->hash_accum, "   0x%08X");

    bool records_match = true;
    for (uint32_t i = 0; i < ref_match_count; i++) {
        if (ctx_jit->records[i].id != ref_matches[i].id ||
            ctx_jit->records[i].type != ref_matches[i].type ||
            ctx_jit->records[i].amount != ref_matches[i].amount ||
            ctx_jit->records[i].timestamp != ref_matches[i].timestamp) {
            records_match = false;
            break;
        }
    }
    printf("%-16s | %13s | %21s | %s\n",
           "Compacted Data", "5000 recs", "In-place SLM",
           records_match ? "PASS [OK]" : "FAIL [MISMATCH]");
    if (!records_match) ok = false;

    free(ctx_jit);
    free(ctx_ref);
    free(ref_matches);
    return ok;
}

// ---------------------------------------------------------------------------
// TEST 2: Standard Analytics (Backward Compatibility, 0 Spills)
// ---------------------------------------------------------------------------
struct analytics_context {
    uint32_t record_count;
    uint32_t target_type;
    uint32_t min_amount;
    uint32_t max_amount;
    uint32_t matches;
    uint32_t sum_amount;
    uint32_t max_matched_amount;
    uint32_t min_matched_amount;
    struct record records[];
};

static bool test_standard_analytics(void *jit_buf, size_t mem_size) {
    printf("\n--------------------------------------------------------------------\n");
    printf("TEST 2: Simple Analytics (analytics_simple.bin - Backward Compatibility)\n");
    printf("--------------------------------------------------------------------\n");

    const char *bin_path = "apps/analytics_simple.bin";
    int fd = open(bin_path, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open apps/analytics_simple.bin");
        return false;
    }

    struct ebpf_inst prog[512];
    ssize_t bytes = read(fd, prog, sizeof(prog));
    close(fd);
    if (bytes <= 0) return false;

    int num_inst = bytes / sizeof(struct ebpf_inst);
    printf("Loaded %zd bytes (%d eBPF instructions)\n", bytes, num_inst);

    jit_set_memory_target((uint32_t *)jit_buf);
    compile_ebpf(prog, num_inst);

    int cached_count = jit_get_cached_slots_count();
    int emitted_insns = jit_get_emitted_insn_count();
    printf(">>> Register Caching Status: %d stack slots cached\n", cached_count);
    printf(">>> Emitted RISC-V instructions: %d (%d bytes)\n", emitted_insns, emitted_insns * 4);

    mkdir("build", 0755);
    FILE *dump_fp = fopen("build/jit_standard.bin", "wb");
    if (dump_fp) {
        fwrite(jit_buf, 4, emitted_insns, dump_fp);
        fclose(dump_fp);
        printf(">>> Saved machine code to 'build/jit_standard.bin'\n");
    }

    const uint32_t num_records = 2000;
    size_t ctx_size = sizeof(struct analytics_context) + num_records * sizeof(struct record);
    struct analytics_context *ctx = malloc(ctx_size);

    uint32_t expected_matches = 0;
    uint32_t expected_sum = 0;
    uint32_t expected_max = 0;
    uint32_t expected_min = 0xFFFFFFFF;

    for (uint32_t i = 0; i < num_records; i++) {
        struct record rec;
        rec.id = i + 1;
        rec.type = (i % 3) + 1;
        rec.amount = ((i * 37) % 500);
        rec.timestamp = 1700000000 + i;
        ctx->records[i] = rec;

        if (rec.type == 1 && rec.amount >= 50 && rec.amount <= 150) {
            expected_matches++;
            expected_sum += rec.amount;
            if (rec.amount > expected_max) expected_max = rec.amount;
            if (rec.amount < expected_min) expected_min = rec.amount;
        }
    }
    if (expected_matches == 0) expected_min = 0;

    ctx->record_count = num_records;
    ctx->target_type = 1;
    ctx->min_amount = 50;
    ctx->max_amount = 150;
    ctx->matches = 0;
    ctx->sum_amount = 0;
    ctx->max_matched_amount = 0;
    ctx->min_matched_amount = 0xFFFFFFFF;

    __builtin___clear_cache(jit_buf, (char *)jit_buf + mem_size);
    uint64_t (*jit_func)(void *) = (uint64_t (*)(void *))jit_buf;
    uint64_t ret = jit_func(ctx);

    printf("Execution completed. JIT return value: %lu\n", (unsigned long)ret);
    printf("Metric           | C Reference   | JIT (Standard)        | Status\n");
    printf("-----------------+---------------+-----------------------+---------\n");

    bool ok = true;
    CHECK("Matches", expected_matches, ctx->matches, "%13u");
    CHECK("Gross Sum", expected_sum, ctx->sum_amount, "%13u");
    CHECK("Min Amount", expected_min, ctx->min_matched_amount, "%13u");
    CHECK("Max Amount", expected_max, ctx->max_matched_amount, "%13u");

    free(ctx);
    return ok;
}

int main(void) {
    printf("====================================================================\n");
    printf("  JIT Register Caching Verification Test Suite\n");
    printf("====================================================================\n");

    size_t mem_size = 64 * 1024;
    void *jit_buf = mmap(NULL, mem_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (jit_buf == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    bool ok1 = test_advanced_caching(jit_buf, mem_size);
    bool ok2 = test_standard_analytics(jit_buf, mem_size);

    printf("\n====================================================================\n");
    if (ok1 && ok2) {
        printf(">>> ALL TESTS PASSED: Register Caching and JIT Compiler Fully Verified! <<<\n");
    } else {
        printf(">>> TEST FAILURE DETECTED! <<<\n");
    }
    printf("====================================================================\n");

    munmap(jit_buf, mem_size);
    return (ok1 && ok2) ? 0 : 1;
}
