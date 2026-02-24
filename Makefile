# --- Variabili ---
CC = riscv64-linux-gnu-gcc
GDB = riscv64-linux-gnu-gdb
QEMU = qemu-system-riscv64

# Flag di compilazione: niente librerie standard, target RV64G
CFLAGS = -march=rv64g -mabi=lp64 -mcmodel=medany -Wall -O0 -g -ffreestanding -nostdlib -Iinclude
LDFLAGS = -T arch/linker.ld -nostdlib -Wl,--no-warn-rwx-segments

# File sorgenti
SRCS = arch/boot.S src/main.c src/jit.c src/utils.c
TARGET = firmware.elf

# --- Regole ---

# Compila il firmware
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS) -o $(TARGET)

# Esegue QEMU normalmente
run: $(TARGET)
	$(QEMU) -machine virt -bios none -kernel $(TARGET) -nographic

# Esegue QEMU in pausa, pronto per GDB
debug: $(TARGET)
	$(QEMU) -machine virt -bios none -kernel $(TARGET) -nographic -S -s

# FIXME
# Lancia QEMU in background e poi GDB in automatico
test: $(TARGET)
	$(QEMU) -machine virt -bios none -kernel $(TARGET) -nographic -S -s & \
	sleep 1 && \
	$(GDB) -batch $(TARGET)

# Pulisce i file compilati
clean:
	rm -f $(TARGET)
