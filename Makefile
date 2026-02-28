# --- Variables ---
CC = riscv64-linux-gnu-gcc
GDB = riscv64-linux-gnu-gdb
QEMU = qemu-system-riscv64

# Compilation flags: no standard libraries, target RV64G
CFLAGS = -march=rv64g -mabi=lp64 -mcmodel=medany -Wall -O0 -g -ffreestanding -nostdlib -Iinclude
LDFLAGS = -T arch/linker.ld -nostdlib -Wl,--no-warn-rwx-segments

# Source files
SRCS = arch/boot.S src/main.c src/jit.c src/utils.c
TARGET = firmware.elf

# --- Rules ---

# Compile the firmware
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS) -o $(TARGET)

# Run QEMU normally
run: $(TARGET)
	$(QEMU) -machine virt -bios none -kernel $(TARGET) -nographic

# Run QEMU in pause mode, ready for GDB
debug: $(TARGET)
	$(QEMU) -machine virt -bios none -kernel $(TARGET) -nographic -S -s

# Clean compiled files
clean:
	rm -f $(TARGET)
