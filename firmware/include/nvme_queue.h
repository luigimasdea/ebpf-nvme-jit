#ifndef NVME_QUEUE_H
#define NVME_QUEUE_H

#include <stdint.h>
#include "nvme_spec.h"

#define NVME_QUEUE_DEPTH 16

/* Physical address for the NVMe Queues (placed at +4KB offset inside QUEUES region) */
#define NVME_QUEUE_BASE  0x222401000ULL

/*
 * NVMe Controller Registers / Doorbells
 * In real PCIe NVMe hardware, these are MMIO registers mapped in BAR0.
 * In our AMP shared-memory setup, they live in shared SRAM/DRAM so both
 * Linux Host and Bare-Metal Core 3 can access them atomically.
 */
struct nvme_controller_regs {
    volatile uint32_t sq_tail;   /* Host -> Core 3: written by Host when a new SQE is added */
    volatile uint32_t cq_head;   /* Host -> Core 3: written by Host when a CQE is consumed */
    volatile uint32_t sq_head;   /* Core 3 -> Host: current SQ head consumed by Firmware */
    volatile uint32_t cq_tail;   /* Core 3 -> Host: current CQ tail written by Firmware */
    volatile uint32_t status;    /* Controller status: 0 = NOT_READY, 1 = READY, 2 = BUSY */
    uint32_t rsvd[3];            /* Padding to align to 32 bytes */
};

/* Controller Status Flags */
#define NVME_STATUS_NOT_READY  0
#define NVME_STATUS_READY      1
#define NVME_STATUS_BUSY       2
#define NVME_STATUS_HALT       3

/*
 * Full NVMe Shared Memory Layout:
 * 1. Registers / Doorbells (32 bytes)
 * 2. Reserved padding to 64-byte alignment
 * 3. Submission Queue (16 entries * 64 bytes = 1024 bytes)
 * 4. Completion Queue (16 entries * 16 bytes = 256 bytes)
 */
struct nvme_queue_mem {
    struct nvme_controller_regs regs;
    uint8_t rsvd[64 - sizeof(struct nvme_controller_regs)];
    struct nvme_sqe sq[NVME_QUEUE_DEPTH];
    struct nvme_cqe cq[NVME_QUEUE_DEPTH];
} __attribute__((packed));

/* Queue Management API for Firmware */
void nvme_queue_init(void);
int  nvme_poll_sq(struct nvme_sqe *out_sqe);
void nvme_post_cqe(uint16_t cid, uint32_t cdw0, uint16_t status);

#endif /* NVME_QUEUE_H */
