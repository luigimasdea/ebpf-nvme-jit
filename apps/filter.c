// Basic types to avoid system header dependencies
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

struct filter_context {
    uint64_t count;      // Number of elements in dataset
    uint64_t threshold;  // Filter threshold condition (val >= threshold)
    uint64_t values[8];  // Data buffer (simulating SLM chunk)
};

// Section 'app' for easy extraction via objcopy
__attribute__((section("app")))
uint64_t app_entry(struct filter_context *ctx) {
    if (!ctx)
        return 0;

    uint64_t matches = 0;
    uint64_t n = ctx->count;
    uint64_t thresh = ctx->threshold;

    for (uint64_t i = 0; i < 8; i++) {
        if (i >= n)
            break;
        if (ctx->values[i] >= thresh) {
            matches++;
        }
    }

    return matches;
}
