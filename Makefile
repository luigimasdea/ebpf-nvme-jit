# ==============================================================================
# eBPF-NVMe-JIT Master Makefile for StarFive VisionFive 2 (AMP Architecture)
# ==============================================================================

APP_SRC ?= apps/analytics.c
APP_BIN ?= apps/app.bin

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
	@echo "  make all       - Build firmware, host monitor, eBPF app, and kick_core"
	@echo "  make firmware  - Build generic bare-metal firmware (firmware/build/firmware.bin)"
	@echo "  make host      - Build userspace host manager (host/host_manager)"
	@echo "  make app       - Compile standalone eBPF app binary (apps/app.bin)"
	@echo "  make kick      - Build kernel module kicker (tools/kick_core/vf2_kick.ko)"
	@echo "  make clean     - Clean all build artifacts"

# 1. Compile standalone eBPF app binary
app: $(APP_SRC)
	@mkdir -p apps/build
	$(BPF_CC) -target bpf -O2 -c $(APP_SRC) -o apps/build/app.o
	$(OBJCOPY) -O binary --only-section=app apps/build/app.o $(APP_BIN)
	@echo "Generated standalone eBPF binary: $(APP_BIN)"

# 2. Sub-module targets
firmware:
	$(MAKE) -C firmware

host:
	$(MAKE) -C host

kick:
	$(MAKE) -C tools/kick_core

clean:
	$(MAKE) -C firmware clean
	$(MAKE) -C host clean
	$(MAKE) -C tools/kick_core clean
	rm -rf firmware/build apps/build $(APP_BIN)
