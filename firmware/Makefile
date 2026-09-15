# --- Toolchain ---
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),riscv64)
  CROSS_COMPILE ?=
else
  CROSS_COMPILE ?= riscv64-linux-gnu-
endif

CC = $(CROSS_COMPILE)gcc
OBJCOPY = $(CROSS_COMPILE)objcopy

# --- Paths ---
INC_DIR = include
SRC_DIR = src
ARCH_DIR = arch
BUILD_DIR = build

# --- Flags ---
# -march=rv64g is compatible with JH7110
CFLAGS = -march=rv64g -mabi=lp64 -mcmodel=medany -Wall -O2 -g -ffreestanding -nostdlib -fno-pic -fno-PIE -I$(INC_DIR)
LDFLAGS = -T $(ARCH_DIR)/linker.ld -nostdlib -Wl,--no-warn-rwx-segments

# --- Sources ---
SRCS = $(ARCH_DIR)/boot.S \
       $(SRC_DIR)/main.c \
       $(SRC_DIR)/jit.c \
       $(SRC_DIR)/nvme_queue.c \
       $(SRC_DIR)/utils.c

TARGET = $(BUILD_DIR)/firmware.elf
BINARY = $(BUILD_DIR)/firmware.bin

# --- Rules ---

all: $(BINARY)

$(TARGET): $(SRCS)
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SRCS) $(LDFLAGS) -o $@

$(BINARY): $(TARGET)
	$(OBJCOPY) -O binary $< $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
