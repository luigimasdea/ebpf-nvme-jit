#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

struct record {
    uint32_t id;
    uint32_t type;       // 1 = SALE, 2 = REFUND, 3 = EXPENSE
    uint32_t amount;     // Transaction amount ($)
    uint32_t timestamp;  // Unix timestamp
};

#define BUFFER_RECORDS 65536 // 1MB buffer (65536 * 16 bytes)

static void print_usage(const char *prog) {
    printf("Usage: %s <output_file> <num_records | size_with_suffix>\n", prog);
    printf("Examples:\n");
    printf("  %s /mnt/nvme/dataset_100k.bin 100000     (100K records = 1.6 MB)\n", prog);
    printf("  %s /mnt/nvme/dataset_1m.bin 1000000      (1M records = 16.0 MB)\n", prog);
    printf("  %s /mnt/nvme/dataset_100mb.bin 100MB     (6.25M records = 100.0 MB)\n", prog);
}

static uint64_t parse_record_count(const char *str) {
    char *endptr;
    double val = strtod(str, &endptr);
    if (val <= 0) return 0;

    if (*endptr == '\0') {
        return (uint64_t)val;
    } else if (strcasecmp(endptr, "k") == 0 || strcasecmp(endptr, "kb") == 0) {
        return (uint64_t)(val * 1024 / sizeof(struct record));
    } else if (strcasecmp(endptr, "m") == 0 || strcasecmp(endptr, "mb") == 0) {
        return (uint64_t)(val * 1024 * 1024 / sizeof(struct record));
    } else if (strcasecmp(endptr, "g") == 0 || strcasecmp(endptr, "gb") == 0) {
        return (uint64_t)(val * 1024 * 1024 * 1024 / sizeof(struct record));
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char *out_path = argv[1];
    uint64_t total_records = parse_record_count(argv[2]);
    if (total_records == 0) {
        fprintf(stderr, "Error: Invalid record count or size: '%s'\n", argv[2]);
        return 1;
    }

    uint64_t total_bytes = total_records * sizeof(struct record);
    printf("====================================================\n");
    printf("[DATASET GENERATOR] NVMe Computational Storage\n");
    printf("====================================================\n");
    printf("  Output File   : %s\n", out_path);
    printf("  Record Count  : %lu records\n", (unsigned long)total_records);
    printf("  File Size     : %.2f MB (%lu bytes)\n", (double)total_bytes / (1024.0 * 1024.0), (unsigned long)total_bytes);
    printf("----------------------------------------------------\n");

    int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        perror("Error opening output file");
        return 1;
    }

    struct record *buffer = malloc(BUFFER_RECORDS * sizeof(struct record));
    if (!buffer) {
        perror("Error allocating write buffer");
        close(fd);
        return 1;
    }

    // Ground truth statistics for Query: type == 1 && amount in [50, 500]
    uint64_t expected_matches = 0;
    uint64_t expected_sum = 0;
    uint32_t expected_min = 0xFFFFFFFF;
    uint32_t expected_max = 0;

    uint32_t base_timestamp = 1700000000;
    uint64_t written_records = 0;

    // Linear Congruential Generator (LCG) for fast, deterministic, reproducible numbers
    uint32_t seed = 42;
    #define FAST_RAND() (seed = seed * 1664525u + 1013904223u)

    printf("[INFO] Generating dataset...\n");

    while (written_records < total_records) {
        uint32_t batch = BUFFER_RECORDS;
        if (total_records - written_records < batch) {
            batch = (uint32_t)(total_records - written_records);
        }

        for (uint32_t i = 0; i < batch; i++) {
            uint64_t current_id = written_records + i + 1;
            uint32_t r_type = (FAST_RAND() % 3) + 1;         // 1=SALE, 2=REFUND, 3=EXPENSE
            uint32_t r_amount = (FAST_RAND() % 1000) + 1;    // Amount between $1 and $1000
            uint32_t r_ts = base_timestamp + (uint32_t)current_id;

            buffer[i].id = (uint32_t)current_id;
            buffer[i].type = r_type;
            buffer[i].amount = r_amount;
            buffer[i].timestamp = r_ts;

            // Compute Ground Truth
            if (r_type == 1 && r_amount >= 50 && r_amount <= 500) {
                expected_matches++;
                expected_sum += r_amount;
                if (r_amount > expected_max) expected_max = r_amount;
                if (r_amount < expected_min) expected_min = r_amount;
            }
        }

        size_t bytes_to_write = batch * sizeof(struct record);
        ssize_t written = write(fd, buffer, bytes_to_write);
        if (written != (ssize_t)bytes_to_write) {
            perror("Error writing to file");
            free(buffer);
            close(fd);
            return 1;
        }

        written_records += batch;
    }

    if (expected_matches == 0) {
        expected_min = 0;
    }

    // Force flush to physical SSD storage
    fsync(fd);
    close(fd);
    free(buffer);

    printf("[SUCCESS] Generated %lu records successfully!\n", (unsigned long)total_records);
    printf("====================================================\n");
    printf("[GROUND TRUTH] Filter: Type == 1 (SALE), Amount in [50, 500]\n");
    printf("  Expected Matches : %lu (%.2f%% of total)\n",
           (unsigned long)expected_matches, (double)expected_matches * 100.0 / (double)total_records);
    printf("  Expected Sum     : $%lu\n", (unsigned long)expected_sum);
    printf("  Expected Min     : $%u\n", expected_min);
    printf("  Expected Max     : $%u\n", expected_max);
    printf("====================================================\n");

    return 0;
}
