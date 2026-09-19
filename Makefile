# ==============================================================================
# eBPF-NVMe-JIT Master Makefile for StarFive VisionFive 2 (AMP Architecture)
# ==============================================================================

APP_SIMPLE_SRC ?= apps/analytics_simple.c
APP_SIMPLE_BIN ?= apps/analytics_simple.bin
APP_ADV_SRC ?= apps/analytics_advanced.c
APP_ADV_BIN ?= apps/analytics_advanced.bin

# Tools
BPF_CC ?= clang
OBJCOPY ?= llvm-objcopy

UNAME_M := $(shell uname -m)

.PHONY: all firmware host kick app clean help

ifeq ($(UNAME_M),riscv64)
all: firmware host app kick
else
all: firmware host app
endif

help:
	@echo "eBPF-NVMe-JIT Build System"
	@echo "Targets:"
	@echo "  make all       - Build firmware, host monitor, eBPF apps, and kick_core"
	@echo "  make firmware  - Build generic bare-metal firmware (firmware/build/firmware.bin)"
	@echo "  make host      - Build userspace host manager (host/host_manager)"
	@echo "  make app       - Compile eBPF app binaries (analytics_simple.bin & analytics_advanced.bin)"
	@echo "  make kick      - Build kernel module kicker (tools/kick_core/vf2_kick.ko)"
	@echo "  make clean     - Clean all build artifacts"

# 1. Compile standalone eBPF app binaries
app: $(APP_SIMPLE_SRC) $(APP_ADV_SRC)
	@mkdir -p apps/build
	$(BPF_CC) -target bpf -O2 -c $(APP_SIMPLE_SRC) -o apps/build/analytics_simple.o
	$(OBJCOPY) -O binary --only-section=app apps/build/analytics_simple.o $(APP_SIMPLE_BIN)
	@echo "Generated simple eBPF binary: $(APP_SIMPLE_BIN)"
	$(BPF_CC) -target bpf -O2 -c $(APP_ADV_SRC) -o apps/build/analytics_advanced.o
	$(OBJCOPY) -O binary --only-section=app apps/build/analytics_advanced.o $(APP_ADV_BIN)
	@echo "Generated advanced eBPF binary: $(APP_ADV_BIN)"

# 2. Sub-module targets
firmware:
	$(MAKE) -C firmware

host:
	$(MAKE) -C host

tools: tools/generate_dataset

tools/generate_dataset: tools/generate_dataset.c
	$(CC) -Wall -O2 $< -o $@

kick:
	$(MAKE) -C tools/kick_core


clean:
	$(MAKE) -C firmware clean
	$(MAKE) -C host clean
	$(MAKE) -C tools/kick_core clean
	rm -rf build firmware/build apps/build $(APP_SIMPLE_BIN) $(APP_ADV_BIN) tools/generate_dataset

