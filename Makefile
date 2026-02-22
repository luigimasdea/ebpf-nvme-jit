# --- Variabili ---
CC = riscv64-linux-gnu-gcc
GDB = riscv64-linux-gnu-gdb
QEMU = qemu-system-riscv64

# Flag di compilazione: niente librerie standard, target RV64G
CFLAGS = -march=rv64g -mabi=lp64 -mcmodel=medany -Wall -O0 -g -ffreestanding -nostdlib -Iinclude
LDFLAGS = -T arch/linker.ld -nostdlib

# File sorgenti
SRCS = arch/boot.S src/main.c src/jit.c
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

# Pulisce i file compilati
clean:
	rm -f $(TARGET)
