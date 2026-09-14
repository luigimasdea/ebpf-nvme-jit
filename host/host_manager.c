#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#define PHYS_BASE       0x222000000ULL
#define MAP_SIZE        0x01000000ULL  // 16MB
#define FW_BINARY       "firmware/build/firmware.bin"

// Virtual Console offsets (Match firmware/src/utils.c)
#define VCON_OFFSET     0x00400000ULL  // 0x222400000
#define VCON_SIZE       4096

int main() {
    int mem_fd, fw_fd;
    uint8_t *map_base;

    printf("[HOST] VisionFive 2 SmartSSD Monitor Started.\n");

    mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd < 0) {
        perror("open /dev/mem");
        return 1;
    }

    map_base = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, PHYS_BASE);
    if (map_base == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // 1. Reset and Clear Virtual Console area (CRITICAL for fresh boot)
    printf("[HOST] Resetting Virtual Console indexes...\n");
    volatile uint32_t *vcon_idx = (uint32_t *)(map_base + VCON_OFFSET + VCON_SIZE - 4);
    volatile char *vcon_buf = (char *)(map_base + VCON_OFFSET);
    *vcon_idx = 0;
    memset((void*)vcon_buf, 0, VCON_SIZE - 4);

    // 2. Inject firmware
    printf("[HOST] Injecting firmware...\n");
    fw_fd = open(FW_BINARY, O_RDONLY);
    if (fw_fd < 0) {
        // Fallback: try one level up if executed from host/ directory
        fw_fd = open("../" FW_BINARY, O_RDONLY);
    }
    
    if (fw_fd >= 0) {
        read(fw_fd, map_base, 0x100000);
        close(fw_fd);
        printf("[HOST] Firmware ready in RAM.\n");
    } else {
        printf("[HOST] WARNING: Could not find firmware binary (tried %s and ../%s). Skipping injection.\n", FW_BINARY, FW_BINARY);
    }

    uint32_t last_read_idx = 0;
    printf("[HOST] Waiting for Core 3 (Load the kernel module now)...\n");
    printf("--- [CORE 3 LOGS START] ---\n");

    while (1) {
        uint32_t current_idx = *vcon_idx;
        
        while (last_read_idx < current_idx) {
            char c = vcon_buf[last_read_idx % (VCON_SIZE - 8)];
            if (c != '\0') {
                putchar(c);
                fflush(stdout);
            }
            last_read_idx++;
        }
        
        usleep(10000); // 10ms check
    }

    munmap(map_base, MAP_SIZE);
    close(mem_fd);
    return 0;
}
