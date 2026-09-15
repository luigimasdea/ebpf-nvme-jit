#include "utils.h"
#include <stdint.h>

// Virtual Console in Shared RAM (visible via SSH through host_manager)
#define VCON_BASE  0x222400000ULL
#define VCON_SIZE  4096

static volatile char *vcon_buf = (char *)VCON_BASE;
static volatile uint32_t *vcon_idx = (uint32_t *)(VCON_BASE + VCON_SIZE - 4);

void uart_print_char(char c) {
    // 1. Virtual Console in RAM (primary for SSH debugging via host_manager)
    uint32_t curr = *vcon_idx;
    vcon_buf[curr % (VCON_SIZE - 8)] = c;
    *vcon_idx = curr + 1;

    // 2. Physical UART (optional secondary for hardware serial header)
    #define UART_THR  0x10000000ULL
    *(volatile uint32_t *)UART_THR = c;
}

void uart_print(const char *s) {
    while (*s) uart_print_char(*s++);
}

void uart_print_int(int n) {
    if (n == 0) { uart_print_char('0'); return; }
    if (n < 0) { uart_print_char('-'); n = -n; }
    char buf[12];
    int i = 0;
    while (n > 0) { buf[i++] = (n % 10) + '0'; n /= 10; }
    while (i > 0) uart_print_char(buf[--i]);
}

void uart_print_uint64(uint64_t n) {
    if (n == 0) { uart_print_char('0'); return; }
    char buf[20];
    int i = 0;
    while (n > 0) { buf[i++] = (n % 10) + '0'; n /= 10; }
    while (i > 0) uart_print_char(buf[--i]);
}

void uart_print_hex(uint32_t n) {
    const char *hex = "0123456789ABCDEF";
    for (int i = 7; i >= 0; i--) uart_print_char(hex[(n >> (i * 4)) & 0xF]);
}

void *memcpy(void *dest, const void *src, uint32_t n) {
    uint8_t *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
    return dest;
}

void *memset(void *s, int c, uint32_t n) {
    uint8_t *p = (uint8_t *)s;
    while (n--) *p++ = (uint8_t)c;
    return s;
}
