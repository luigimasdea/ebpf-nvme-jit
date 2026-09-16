typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

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
    uint32_t discount_pct;      // e.g. 15 (means 15% discount, net = amount * 85 / 100)
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

    // --- Dataset in SLM (in-place filtered records will be packed at index 0..matches-1) ---
    struct record records[];
};

__attribute__((section("app")))
uint64_t app_entry(struct advanced_context *ctx) {
    if (!ctx)
        return 0;

    uint32_t n = ctx->record_count;
    uint32_t target_type = ctx->target_type;
    uint32_t min_amt = ctx->min_amount;
    uint32_t max_amt = ctx->max_amount;
    uint32_t min_ts = ctx->min_timestamp;
    uint32_t max_ts = ctx->max_timestamp;
    uint32_t disc = ctx->discount_pct;
    uint32_t multiplier = (disc < 100) ? (100 - disc) : 100;

    uint32_t match_count = 0;
    uint32_t sum = 0;
    uint32_t net_sum = 0;
    uint32_t max_val = 0;
    uint32_t min_val = 0xFFFFFFFF;
    uint32_t hash = 0x811C9DC5; // FNV-1a 32-bit offset basis

    for (uint32_t i = 0; i < n; i++) {
        uint32_t r_id = ctx->records[i].id;
        uint32_t r_type = ctx->records[i].type;
        uint32_t r_amt = ctx->records[i].amount;
        uint32_t r_ts = ctx->records[i].timestamp;

        // Multi-attribute predicate (Type, Amount Range, Timestamp Range)
        if (r_type == target_type &&
            r_amt >= min_amt && r_amt <= max_amt &&
            r_ts >= min_ts && r_ts <= max_ts) {

            // 1. In-place stream compaction: move matching record to the front of SLM
            ctx->records[match_count].id = r_id;
            ctx->records[match_count].type = r_type;
            ctx->records[match_count].amount = r_amt;
            ctx->records[match_count].timestamp = r_ts;

            // 2. Metrics aggregation
            match_count++;
            sum += r_amt;

            // 3. Discount calculation: (amount * (100 - disc)) / 100
            uint32_t net_val = (r_amt * multiplier) / 100;
            net_sum += net_val;

            if (r_amt > max_val) max_val = r_amt;
            if (r_amt < min_val) min_val = r_amt;

            // 4. Record partition / integrity hash (FNV-1a mix with bit rotation)
            hash ^= r_id;
            hash = (hash * 16777619) ^ (r_amt << 1);
            hash ^= (r_ts >> 3);
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
    ctx->hash_accum = hash;
    ctx->net_discount_sum = net_sum;

    // Return the match count in R0 (transmitted via NVMe CQE CDW0)
    return match_count;
}
