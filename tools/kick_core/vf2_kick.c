#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cpu.h>
#include <asm/sbi.h>

#define SBI_EXT_HSM                 0x48534D
#define SBI_HSM_HART_START          0
#define SBI_HSM_HART_STOP           1
#define SBI_HSM_HART_GET_STATUS     2

#define SBI_HSM_STATE_STARTED       0
#define SBI_HSM_STATE_STOPPED       1

static int target_hart = 4;
module_param(target_hart, int, 0644);
MODULE_PARM_DESC(target_hart, "Target Hart ID (default: 4 for VF2 Core 3)");

static int target_cpu = 3;
module_param(target_cpu, int, 0644);
MODULE_PARM_DESC(target_cpu, "Linux CPU index to check (default: 3)");

static unsigned long start_addr = 0x222000000ULL;
module_param(start_addr, ulong, 0644);
MODULE_PARM_DESC(start_addr, "Physical entry point of firmware (default: 0x222000000)");

static int __init vf2_kick_init(void) {
    struct sbiret ret;

    pr_info("[VF2_KICK] === Starting Bare-Metal Boot Sequence ===\n");
    pr_info("[VF2_KICK] Target: Hart %d (CPU %d) at physical address 0x%lx\n",
            target_hart, target_cpu, start_addr);

    // 1. Ensure Linux has released this CPU
    if (cpu_online(target_cpu)) {
        pr_err("[VF2_KICK] ERROR: Linux CPU %d is still active and owned by Linux!\n", target_cpu);
        pr_err("[VF2_KICK] You must offline it first by running on host:\n");
        pr_err("[VF2_KICK]   echo 0 | sudo tee /sys/devices/system/cpu/cpu%d/online\n", target_cpu);
        return -EBUSY;
    }

    // 2. Query Hart state in OpenSBI
    ret = sbi_ecall(SBI_EXT_HSM, SBI_HSM_HART_GET_STATUS, target_hart, 0, 0, 0, 0, 0);
    if (ret.error) {
        pr_err("[VF2_KICK] SBI error getting status for Hart %d: %ld\n", target_hart, ret.error);
        return -EIO;
    }

    if (ret.value != SBI_HSM_STATE_STOPPED) {
        pr_err("[VF2_KICK] Hart %d is NOT in STOPPED state (state=%ld). Cannot boot.\n",
               target_hart, ret.value);
        return -EINVAL;
    }

    pr_info("[VF2_KICK] Hart %d is STOPPED. Calling SBI HART_START...\n", target_hart);

    // 3. Boot Hart via SBI HSM HART_START
    // arg0 = target_hart, arg1 = start_addr (physical), arg2 = opaque parameter
    ret = sbi_ecall(SBI_EXT_HSM, SBI_HSM_HART_START, target_hart, start_addr, 0, 0, 0, 0);
    if (ret.error) {
        pr_err("[VF2_KICK] SBI HART_START failed with error: %ld\n", ret.error);
        return -EIO;
    }

    pr_info("[VF2_KICK] SUCCESS: Hart %d booted cleanly into bare-metal!\n", target_hart);
    return 0;
}

static void __exit vf2_kick_exit(void) {
    pr_info("[VF2_KICK] Module unloaded.\n");
}

module_init(vf2_kick_init);
module_exit(vf2_kick_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luigi Masdea");
MODULE_DESCRIPTION("Minimal SBI HSM Core Kicker for StarFive VisionFive 2");
