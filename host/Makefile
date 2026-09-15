CC = gcc
CFLAGS = -Wall -O2 -I../firmware/include

TARGETS = host_manager host_benchmark

all: $(TARGETS)

host_manager: host_manager.c
	$(CC) $(CFLAGS) $< -o $@

host_benchmark: host_benchmark.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGETS)

.PHONY: all clean
