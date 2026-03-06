# --- Path Configurations ---
APP_SRC ?= apps/main.c
BUILD_DIR = build
GEN_DIR = include/gen

# --- Toolchain ---
CC = riscv64-linux-gnu-gcc
BPF_CC = clang
OBJCOPY = llvm-objcopy
QEMU = qemu-system-riscv64

# --- RISC-V Build Flags ---
CFLAGS = -march=rv64g -mabi=lp64 -mcmodel=medany -Wall -O0 -g -ffreestanding -nostdlib -Iinclude
LDFLAGS = -T arch/linker.ld -nostdlib -Wl,--no-warn-rwx-segments

# --- eBPF Compilation Flags ---
BPF_CFLAGS = -target bpf -O2 -c -Iinclude

# --- JIT Firmware Source Files ---
SRCS = arch/boot.S src/main.c src/jit.c src/utils.c
TARGET = firmware.elf

# --- Automation Workflow ---

all: $(TARGET)

# 1. Create build and generation directories
prepare:
	mkdir -p $(BUILD_DIR) $(GEN_DIR)

# 2. Compile host-side C app to eBPF object file
$(BUILD_DIR)/app.o: $(APP_SRC) | prepare
	$(BPF_CC) $(BPF_CFLAGS) $(APP_SRC) -o $@

# 3. Extract the raw bytecode section 'app' from the object file
$(BUILD_DIR)/app.bin: $(BUILD_DIR)/app.o
	$(OBJCOPY) -O binary --only-section=app $< $@

# 4. Generate C header from the raw binary for inclusion in JIT firmware
$(GEN_DIR)/app_data.h: $(BUILD_DIR)/app.bin
	cp $(BUILD_DIR)/app.bin app_bin
	xxd -i app_bin > $@
	rm app_bin

# 5. Compile the final JIT firmware ELF
$(TARGET): $(GEN_DIR)/app_data.h $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS) -o $(TARGET)

run: $(TARGET)
	$(QEMU) -machine virt -bios none -kernel $(TARGET) -nographic

clean:
	rm -rf $(TARGET) $(BUILD_DIR) $(GEN_DIR)
