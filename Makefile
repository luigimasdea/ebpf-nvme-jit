# ==============================================================================
# eBPF-NVMe-JIT Master Makefile for StarFive VisionFive 2 (AMP Architecture)
# ==============================================================================

APP_SRC ?= apps/filter.c
GEN_HEADER = firmware/include/gen/app_data.h

# Tools
BPF_CC ?= clang
OBJCOPY ?= llvm-objcopy
XXD ?= xxd

.PHONY: all firmware host kick app clean help

all: firmware host kick

help:
	@echo "eBPF-NVMe-JIT Build System"
	@echo "Targets:"
	@echo "  make all       - Build firmware, host monitor, and kick_core module"
	@echo "  make firmware  - Build bare-metal firmware (build/firmware.bin)"
	@echo "  make host      - Build userspace host manager (host/host_manager)"
	@echo "  make kick      - Build kernel module kicker (tools/kick_core/vf2_kick.ko)"
	@echo "  make app       - Compile eBPF app (default: APP_SRC=apps/main.c) into bytecode header"
	@echo "  make clean     - Clean all build artifacts"

# 1. Compile eBPF app to C header in firmware
app: $(APP_SRC)
	@mkdir -p firmware/include/gen firmware/build
	$(BPF_CC) -target bpf -O2 -c $(APP_SRC) -o firmware/build/app.o
	$(OBJCOPY) -O binary --only-section=app firmware/build/app.o firmware/build/app.bin
	cd firmware/build && cp app.bin app_bin && $(XXD) -i app_bin > ../include/gen/app_data.h && rm app_bin
	@echo "Generated $(GEN_HEADER) from $(APP_SRC)"

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
	rm -rf firmware/build
