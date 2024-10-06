# Compiler and flags
CC = gcc
CFLAGS = -g 

# Source files and headers
SRCS = dns-monitor.c parse_args.c 
HEADERS = dns-monitor.h parse_args.h lib.h

# Object files
OBJS = $(SRCS:.c=.o)

# Executable name
TARGET = dns-monitor

# Targets
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean