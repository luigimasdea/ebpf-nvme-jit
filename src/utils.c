#include "utils.h"

void uart_print(const char *s) {
    volatile char *uart = (volatile char *)0x10000000;
    while (*s) {
        *uart = *s++;
    }
}

void uart_print_int(int n) {
    char buf[12];
    int i = 10;
    buf[i--] = '\0';
    if (n == 0) buf[i--] = '0';
    while (n > 0 && i >= 0) {
        buf[i--] = (n % 10) + '0';
        n /= 10;
    }
    uart_print(&buf[i+1]);
}
