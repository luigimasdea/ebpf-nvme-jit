// Basic types to avoid system header dependencies
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

struct context {
    uint64_t data;
};

// Section 'app' for easy extraction via objcopy
__attribute__((section("app")))
uint64_t app_entry(struct context *ctx) {
    if (ctx->data == 0)
        return 0;
    
    uint64_t val = ctx->data;
    
    // Example math operation
    val = val + 5;
    
    return val;
}
