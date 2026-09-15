#ifndef NVME_SPEC_H
#define NVME_SPEC_H

#include <stdint.h>

/* NVMe TP4091 Computational Programs Opcodes (Vendor Specific range) */
#define NVME_CMD_EBPF_LOAD     0xC0
#define NVME_CMD_EBPF_ACTIVATE 0xC1
#define NVME_CMD_EBPF_EXECUTE  0xC2
#define NVME_CMD_EBPF_UNLOAD   0xC3

/* Submission Queue Entry (SQE) - 64 Bytes */
struct nvme_sqe {
    uint8_t  opcode;     /* Opcode (e.g., NVME_CMD_EBPF_EXECUTE) */
    uint8_t  flags;      /* Flags (FUSE, PSDT, etc.) */
    uint16_t cid;        /* Command Identifier */
    uint32_t nsid;       /* Namespace Identifier */

    uint64_t rsvd2;      /* Reserved */
    uint64_t mptr;       /* Metadata Pointer */
    uint64_t prp1;       /* Data Pointer 1 (e.g., Memory address for eBPF prog/data) */
    uint64_t prp2;       /* Data Pointer 2 */

    /* Command specific Dwords */
    uint32_t cdw10;
    int32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} __attribute__((packed));

/* Completion Queue Entry (CQE) - 16 Bytes */
struct nvme_cqe {
    uint32_t cdw0;       /* Command Specific (e.g., eBPF return value) */
    uint32_t rsvd1;      /* Reserved */
    uint16_t sq_head;    /* SQ Head Pointer (lets Host know what's been consumed) */
    uint16_t sq_id;      /* SQ Identifier */
    uint16_t cid;        /* Command Identifier (matches SQE cid) */
    uint16_t status;     /* Status Field (includes Phase Tag to indicate new CQE) */
} __attribute__((packed));

#endif /* NVME_SPEC_H */
