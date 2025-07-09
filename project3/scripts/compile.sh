#!/bin/bash

# Poseidon2 Circuit Compilation Script
echo "🔧 Compiling Poseidon2 circuits..."

# Create output directories
mkdir -p build/circuits
mkdir -p build/js
mkdir -p build/wasm

# Set circom options
CIRCOM_OPTIONS="--r1cs --wasm --sym --c"

echo "📋 Compiling test circuit..."
circom circuits/test_poseidon2.circom $CIRCOM_OPTIONS --output build/circuits

echo "📋 Compiling main circuit..."
circom circuits/main.circom $CIRCOM_OPTIONS --output build/circuits

# Move generated files to organized directories
echo "📁 Organizing build files..."

# Move WASM files
if [ -d "build/circuits/test_poseidon2_js" ]; then
    mv build/circuits/test_poseidon2_js/* build/js/
    rmdir build/circuits/test_poseidon2_js
fi

if [ -d "build/circuits/main_c_js" ]; then
    mv build/circuits/main_c_js/* build/js/
    rmdir build/circuits/main_c_js
fi

# Move WASM binaries to wasm directory
mv build/js/*.wasm build/wasm/ 2>/dev/null || true

# Display compilation results
echo "✅ Compilation complete!"
echo ""
echo "📊 Generated files:"
echo "   R1CS files: $(find build/circuits -name "*.r1cs" | wc -l)"
echo "   Symbol files: $(find build/circuits -name "*.sym" | wc -l)"
echo "   JavaScript files: $(find build/js -name "*.js" | wc -l)"
echo "   WASM files: $(find build/wasm -name "*.wasm" | wc -l)"
echo ""

# Show circuit statistics
echo "🔍 Circuit statistics:"
if [ -f "build/circuits/main.r1cs" ]; then
    echo "Main circuit constraints: $(snarkjs r1cs info build/circuits/main.r1cs | grep "Constraints" || echo "Unable to get constraint count")"
fi

if [ -f "build/circuits/test_poseidon2.r1cs" ]; then
    echo "Test circuit constraints: $(snarkjs r1cs info build/circuits/test_poseidon2.r1cs | grep "Constraints" || echo "Unable to get constraint count")"
fi

echo ""
echo "🎯 Next steps:"
echo "   1. Run tests: npm test"
echo "   2. Setup trusted setup: ./scripts/setup.sh"
echo "   3. Generate proofs: npm run prove"
