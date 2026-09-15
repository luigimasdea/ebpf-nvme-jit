typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

struct record {
    uint32_t id;
    uint32_t type;       // e.g., 1 = SALE, 2 = REFUND, 3 = EXPENSE
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

__attribute__((section("app")))
uint64_t app_entry(struct analytics_context *ctx) {
    if (!ctx)
        return 0;

    uint32_t n = ctx->record_count;
    uint32_t target_type = ctx->target_type;
    uint32_t min_amt = ctx->min_amount;
    uint32_t max_amt = ctx->max_amount;

    uint32_t match_count = 0;
    uint32_t sum = 0;
    uint32_t max_val = 0;
    uint32_t min_val = 0xFFFFFFFF;

    for (uint32_t i = 0; i < 16; i++) {
        if (i >= n)
            break;

        uint32_t r_type = ctx->records[i].type;
        uint32_t r_amt = ctx->records[i].amount;

        // Multi-condition filtering predicate
        if (r_type == target_type && r_amt >= min_amt && r_amt <= max_amt) {
            match_count++;
            sum += r_amt;

            if (r_amt > max_val) {
                max_val = r_amt;
            }
            if (r_amt < min_val) {
                min_val = r_amt;
            }
        }
    }

    if (match_count == 0) {
        min_val = 0;
    }

    // Write computed results back to SLM
    ctx->matches = match_count;
    ctx->sum_amount = sum;
    ctx->max_matched_amount = max_val;
    ctx->min_matched_amount = min_val;

    // Return the match count in R0 (transmitted via NVMe CQE CDW0)
    return match_count;
}
