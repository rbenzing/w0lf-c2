# Makefile for client

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -m64 -Wall -Wextra -O2

# Libraries
LIBS = -lws2_32 -lssl -lcrypto

# Source files
SRC = client.c

# Header files
HEADERS = client.h

# Output executable
TARGET = client.exe

# Default target
all: $(TARGET)

# Compile the executable
$(TARGET): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LIBS)

# Clean up
clean:
	del $(TARGET)

# Phony targets
.PHONY: all clean