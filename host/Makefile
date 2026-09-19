CC = gcc
CFLAGS = -Wall -O2 -I../firmware/include

TARGETS = host_manager host_benchmark host_advanced_loader host_ram_loader

all: $(TARGETS)

host_manager: host_manager.c
	$(CC) $(CFLAGS) $< -o $@

host_benchmark: host_benchmark.c
	$(CC) $(CFLAGS) $< -o $@ -lm

host_advanced_loader: host_advanced_loader.c
	$(CC) $(CFLAGS) -pthread $< -o $@

host_ram_loader: host_ram_loader.c
	$(CC) $(CFLAGS) -pthread $< -o $@


clean:
	rm -f $(TARGETS)

.PHONY: all clean
