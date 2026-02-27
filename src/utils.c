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
    
    char buf[12];
    int i = 10;
    buf[i--] = '\0';
    
    int is_negative = 0;
    if (n < 0) {
        is_negative = 1;
        n = -n; // Make it positive for the math loop
    }
    
    while (n > 0 && i >= 0) {
        buf[i--] = (n % 10) + '0';
        n /= 10;
    }
    
    if (is_negative) {
        buf[i--] = '-';
    }
    
    uart_print(&buf[i+1]);
}

void uart_print_hex(uint32_t n) {
    char hex_chars[] = "0123456789abcdef";
    char buf[9];
    buf[8] = '\0';
    for (int i = 7; i >= 0; i--) {
        buf[i] = hex_chars[n & 0xf];
        n >>= 4;
    }
    uart_print(buf);
}
