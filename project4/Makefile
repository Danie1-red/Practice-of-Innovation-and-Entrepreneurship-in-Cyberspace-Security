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
TARGET_LENGTH_ATTACK = length_extension_attack
TARGET_MERKLE = merkle_tree
TARGET_MERKLE_SIMPLE = merkle_tree_simple
TARGET_MERKLE_RFC6962 = merkle_tree_rfc6962

SOURCES = sm3.c
ATTACK_SOURCES = length_extension_attack.c
MERKLE_SOURCES = merkle_tree.c
MERKLE_SIMPLE_SOURCES = merkle_tree_simple.c
MERKLE_RFC6962_SOURCES = merkle_tree_rfc6962.c

.PHONY: all clean test performance debug optimized attack merkle merkle-simple merkle-rfc6962 test-merkle test-merkle-simple test-merkle-rfc6962 help

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

# Length extension attack build
attack: $(TARGET_LENGTH_ATTACK)
$(TARGET_LENGTH_ATTACK): $(ATTACK_SOURCES)
	$(CC) $(CFLAGS) -o $@ $^
	@echo "Length extension attack program built successfully!"

# Merkle tree build
merkle: $(TARGET_MERKLE)
$(TARGET_MERKLE): $(MERKLE_SOURCES)
	$(CC) $(CFLAGS) -lm -o $@ $^
	@echo "Merkle tree program built successfully!"

# Simplified Merkle tree build
merkle-simple: $(TARGET_MERKLE_SIMPLE)
$(TARGET_MERKLE_SIMPLE): $(MERKLE_SIMPLE_SOURCES)
	$(CC) $(CFLAGS) -lm -o $@ $^
	@echo "Simplified Merkle tree program built successfully!"

# RFC6962 Merkle tree build
merkle-rfc6962: $(TARGET_MERKLE_RFC6962)
$(TARGET_MERKLE_RFC6962): $(MERKLE_RFC6962_SOURCES)
	$(CC) $(CFLAGS) -lm -o $@ $^
	@echo "RFC6962 Merkle tree program built successfully!"

# Run tests
test: $(TARGET)
	@echo "Running SM3 implementation tests..."
	./$(TARGET)

# Run performance benchmarks
performance: $(TARGET_OPTIMIZED)
	@echo "Running performance benchmark with advanced optimizations..."
	./$(TARGET_OPTIMIZED)

# Run length extension attack demonstration
test-attack: $(TARGET_LENGTH_ATTACK)
	@echo "Running SM3 length extension attack demonstration..."
	./$(TARGET_LENGTH_ATTACK)

# Run Merkle tree demonstration
test-merkle: $(TARGET_MERKLE)
	@echo "Running SM3-based Merkle tree demonstration..."
	./$(TARGET_MERKLE)

# Run simplified Merkle tree demonstration
test-merkle-simple: $(TARGET_MERKLE_SIMPLE)
	@echo "Running simplified SM3-based Merkle tree demonstration..."
	./$(TARGET_MERKLE_SIMPLE)

# Run RFC6962 Merkle tree demonstration
test-merkle-rfc6962: $(TARGET_MERKLE_RFC6962)
	@echo "Running RFC6962 SM3-based Merkle tree demonstration..."
	./$(TARGET_MERKLE_RFC6962)

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
	rm -f $(TARGET) $(TARGET_DEBUG) $(TARGET_OPTIMIZED) $(TARGET_LENGTH_ATTACK) $(TARGET_MERKLE) $(TARGET_MERKLE_SIMPLE) $(TARGET_MERKLE_RFC6962)
	@echo "Cleaned build artifacts."

# Show help
help:
	@echo "SM3 Implementation - Available targets:"
	@echo "  all         - Build default version (default)"
	@echo "  debug       - Build debug version with symbols"
	@echo "  optimized   - Build with maximum optimization"
	@echo "  attack      - Build length extension attack program"
	@echo "  merkle      - Build Merkle tree program"
	@echo "  merkle-simple - Build simplified Merkle tree program"
	@echo "  test        - Run implementation tests"
	@echo "  performance - Run performance benchmark"
	@echo "  test-attack - Run length extension attack demonstration"
	@echo "  test-merkle - Run Merkle tree demonstration"
	@echo "  test-merkle-simple - Run simplified Merkle tree demonstration"
	@echo "  compare     - Compare optimization levels"
	@echo "  clean       - Remove build artifacts"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Implementation: Based on 20250710-fu-SM3-public.pdf"
	@echo "Security Analysis: Length extension attack verified"
	@echo "Merkle Tree: RFC6962 compliant with 100K node support"
	@echo "Compilation flags:"
	@echo "  Standard:  $(CFLAGS)"
	@echo "  Debug:     $(CFLAGS_DEBUG)"
	@echo "  Optimized: $(CFLAGS_OPTIMIZED)"
