CC = gcc
CFLAGS = -Wall -O2 -I../shared

TARGET = host_manager
SRCS = host_manager.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean
