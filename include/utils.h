#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

void uart_print(const char *s);
void uart_print_int(int n);
void uart_print_uint64(uint64_t n);
void uart_print_hex(uint32_t n);

#endif // !UTILS_H

