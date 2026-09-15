#include "nvme_queue.h"
#include "utils.h"

static volatile struct nvme_queue_mem *qmem = (struct nvme_queue_mem *)NVME_QUEUE_BASE;

/**
 * Initialize NVMe Queue structures and Doorbells in shared memory.
 */
void nvme_queue_init(void) {
    qmem->regs.sq_tail = 0;
    qmem->regs.sq_head = 0;
    qmem->regs.cq_tail = 0;
    qmem->regs.cq_head = 0;

    // Ensure all zeroed memory is visible before setting READY state
    asm volatile("fence rw, rw" ::: "memory");

    qmem->regs.status = NVME_STATUS_READY;
    asm volatile("fence rw, rw" ::: "memory");

    uart_print("[NVMe Queue] Initialized at 0x222401000, Status: READY\n");
}

/**
 * Check if the Host has submitted any new command to the Submission Queue.
 * Returns 1 if a command was fetched into out_sqe, 0 otherwise.
 */
int nvme_poll_sq(struct nvme_sqe *out_sqe) {
    // If tail == head, queue is empty (no pending commands from Host)
    if (qmem->regs.sq_head == qmem->regs.sq_tail) {
        return 0;
    }

    // Ensure we read the new SQE after seeing the updated sq_tail
    asm volatile("fence r, r" ::: "memory");

    uint32_t head_idx = qmem->regs.sq_head % NVME_QUEUE_DEPTH;
    *out_sqe = qmem->sq[head_idx];

    // Advance head to indicate we have consumed this command
    qmem->regs.sq_head++;
    asm volatile("fence rw, rw" ::: "memory");

    return 1;
}

/**
 * Post a Completion Queue Entry (CQE) back to the Host.
 */
void nvme_post_cqe(uint16_t cid, uint32_t cdw0, uint32_t rsvd1, uint16_t status) {
    uint32_t tail_idx = qmem->regs.cq_tail % NVME_QUEUE_DEPTH;

    qmem->cq[tail_idx].cdw0 = cdw0;
    qmem->cq[tail_idx].rsvd1 = rsvd1;
    qmem->cq[tail_idx].sq_head = (uint16_t)qmem->regs.sq_head;
    qmem->cq[tail_idx].sq_id = 0;
    qmem->cq[tail_idx].cid = cid;
    qmem->cq[tail_idx].status = status;

    // Ensure CQE payload is completely written before advancing cq_tail
    asm volatile("fence rw, rw" ::: "memory");

    qmem->regs.cq_tail++;
    asm volatile("fence rw, rw" ::: "memory");
}
