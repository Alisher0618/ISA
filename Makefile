# Compiler and flags
CC = gcc
CFLAGS = -g -std=gnu17 -Wall -Wextra -pedantic  # Debugging info (-g) and strict warnings

# Linker flags
LDFLAGS = -lpcap  # Linker flag for the pcap library (for packet capture)

# Source files and headers
SRCS = dns-monitor.c parse_args.c
HEADERS = dns-monitor.h parse_args.h lib.h

# Object files (generated from source files)
OBJS = $(SRCS:.c=.o)

# Executable name
TARGET = dns-monitor

# Default target (builds the executable)
all: $(TARGET)

# Rule to create the executable by linking object files
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Rule to compile .c files into .o object files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up object files and executable
clean:
	rm -f $(OBJS) $(TARGET)

# Phony targets (to avoid conflicts with filenames)
.PHONY: all clean
