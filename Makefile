# Compiler and flags
CC = gcc
CFLAGS = -g -std=gnu17 -Wall -Wextra -pedantic

# Linker flags
LDFLAGS = -lpcap

# Source files and headers
SRCS = dns-monitor.c parse_args.c
HEADERS = dns-monitor.h parse_args.h

# Object files
OBJS = $(SRCS:.c=.o)

# Executable name
TARGET = dns-monitor

# Default target
all: $(TARGET)

# Rule to link object files into the executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Rule to compile .c files into .o files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to create a tarball for submission
pack:
	tar -cf xmazhi00.tar dns-monitor.c dns-monitor.h parse_args.c parse_args.h manual.pdf Makefile README pcap_files pcap_output

# Clean up
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean pack
