CC = gcc
CFLAGS = -Wall -O2 -I../firmware/include

TARGETS = host_benchmark host_loader

all: $(TARGETS)

host_benchmark: host_benchmark.c
	$(CC) $(CFLAGS) $< -o $@ -lm

host_loader: host_loader.c
	$(CC) $(CFLAGS) -pthread $< -o $@

clean:
	rm -f $(TARGETS) host_manager host_advanced_loader host_ram_loader

.PHONY: all clean
