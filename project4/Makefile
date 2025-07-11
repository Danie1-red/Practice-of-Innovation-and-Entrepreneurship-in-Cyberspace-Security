# SM3 Hash Algorithm Implementation Makefile
# Project 4: SM3 Software Implementation and Optimization
# Based on SM3 Cryptographic Hash Function Standards

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
CFLAGS_DEBUG = -Wall -Wextra -g -DDEBUG -std=c99
CFLAGS_OPTIMIZED = -Wall -Wextra -O3 -march=native -std=c99

# Main implementation targets
TARGET = sm3
TARGET_DEBUG = sm3_debug
TARGET_OPTIMIZED = sm3_optimized

SOURCES = sm3.c

.PHONY: all clean test performance debug optimized help

# Default target - main implementation
all: $(TARGET)

# Standard build
$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^
	@echo "SM3 implementation built successfully!"

# Debug build
debug: $(TARGET_DEBUG)
$(TARGET_DEBUG): $(SOURCES)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^
	@echo "Debug SM3 implementation built successfully!"

# Highly optimized build
optimized: $(TARGET_OPTIMIZED)
$(TARGET_OPTIMIZED): $(SOURCES)
	$(CC) $(CFLAGS_OPTIMIZED) -o $@ $^
	@echo "Optimized SM3 implementation built successfully!"

# Run tests
test: $(TARGET)
	@echo "Running SM3 implementation tests..."
	./$(TARGET)

# Run performance benchmarks
performance: $(TARGET_OPTIMIZED)
	@echo "Running performance benchmark with advanced optimizations..."
	./$(TARGET_OPTIMIZED)

# Compare different optimization levels
compare: $(TARGET) $(TARGET_OPTIMIZED)
	@echo "=== SM3 Performance Comparison ==="
	@echo "Standard optimization (-O2):"
	time ./$(TARGET) > /dev/null 2>&1
	@echo ""
	@echo "High optimization (-O3 -march=native):"
	time ./$(TARGET_OPTIMIZED) > /dev/null 2>&1

# Clean build artifacts
clean:
	rm -f $(TARGET) $(TARGET_DEBUG) $(TARGET_OPTIMIZED)
	@echo "Cleaned build artifacts."

# Show help
help:
	@echo "SM3 Implementation - Available targets:"
	@echo "  all         - Build default version (default)"
	@echo "  debug       - Build debug version with symbols"
	@echo "  optimized   - Build with maximum optimization"
	@echo "  test        - Run implementation tests"
	@echo "  performance - Run performance benchmark"
	@echo "  compare     - Compare optimization levels"
	@echo "  clean       - Remove build artifacts"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Implementation: Based on 20250710-fu-SM3-public.pdf"
	@echo "Compilation flags:"
	@echo "  Standard:  $(CFLAGS)"
	@echo "  Debug:     $(CFLAGS_DEBUG)"
	@echo "  Optimized: $(CFLAGS_OPTIMIZED)"
	@echo "  Optimized: $(CFLAGS_OPTIMIZED)"
