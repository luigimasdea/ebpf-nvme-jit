#include "utils.h"

void uart_print(const char *s) {
    volatile char *uart = (volatile char *)0x10000000;
    while (*s) {
        *uart = *s++;
    }
}

void uart_print_int(int n) {
    if (n == 0) {
        uart_print("0");
        return;
    }
    if (n < 0) {
        uart_print("-");
        n = -n;
    }
    char buf[12];
    int i = 10;
    buf[11] = '\0';
    while (n > 0) {
        buf[i--] = (n % 10) + '0';
        n /= 10;
    }
    uart_print(&buf[i + 1]);
}

void uart_print_uint64(uint64_t n) {
    if (n == 0) {
        uart_print("0");
        return;
    }
    char buf[21];
    int i = 19;
    buf[20] = '\0';
    while (n > 0) {
        buf[i--] = (n % 10) + '0';
        n /= 10;
    }
    uart_print(&buf[i + 1]);
}

void uart_print_hex(uint32_t n) {
    const char *hex = "0123456789ABCDEF";
    for (int i = 7; i >= 0; i--) {
        uart_print_char(hex[(n >> (i * 4)) & 0xF]);
    }
}

void uart_print_char(char c) {
    volatile char *uart = (volatile char *)0x10000000;
    *uart = c;
}
