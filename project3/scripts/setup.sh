#!/bin/bash

# Poseidon2 Trusted Setup Script for Groth16
echo "🔐 Setting up Groth16 trusted setup for Poseidon2 circuits..."

# Check if R1CS files exist
if [ ! -f "build/circuits/main_c.r1cs" ]; then
    echo "❌ main_c.r1cs not found. Please run ./scripts/compile.sh first"
    exit 1
fi

# Create keys directory
mkdir -p build/keys

echo "🎲 Generating random entropy for ceremony..."

# Phase 1: Powers of Tau ceremony
echo "📊 Phase 1: Powers of Tau ceremony..."
echo "   Generating initial ceremony file..."

# For small circuits, we can use a small power of tau
# For production, use larger values and contribute to existing ceremony
POWER=14  # 2^14 = 16384 constraints (adjust based on your circuit size)

# Start new ceremony (for testing - in production, download existing ptau)
npx snarkjs powersoftau new bn128 $POWER build/keys/pot${POWER}_0000.ptau -v

# Contribute to ceremony
echo "   Contributing to ceremony..."
npx snarkjs powersoftau contribute build/keys/pot${POWER}_0000.ptau build/keys/pot${POWER}_0001.ptau \
    --name="First contribution" -v -e="$(openssl rand -hex 32)"

# Add second contribution for additional security
echo "   Adding second contribution..."
npx snarkjs powersoftau contribute build/keys/pot${POWER}_0001.ptau build/keys/pot${POWER}_0002.ptau \
    --name="Second contribution" -v -e="$(openssl rand -hex 32)"

# Phase 2: Circuit-specific setup
echo "📊 Phase 2: Circuit-specific setup..."

# Apply random beacon (finalize Phase 1)
echo "   Finalizing Phase 1..."
npx snarkjs powersoftau beacon build/keys/pot${POWER}_0002.ptau build/keys/pot${POWER}_beacon.ptau \
    0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon"

# Prepare Phase 2
echo "   Preparing Phase 2..."
npx snarkjs powersoftau prepare phase2 build/keys/pot${POWER}_beacon.ptau build/keys/pot${POWER}_final.ptau -v

# Generate circuit-specific setup
echo "   Generating proving and verification keys..."
npx snarkjs groth16 setup build/circuits/main_c.r1cs build/keys/pot${POWER}_final.ptau build/keys/main_0000.zkey

# Contribute to circuit-specific ceremony
echo "   Contributing to circuit-specific setup..."
npx snarkjs zkey contribute build/keys/main_0000.zkey build/keys/main_0001.zkey \
    --name="Circuit contribution 1" -v -e="$(openssl rand -hex 32)"

# Add second contribution
echo "   Adding second circuit contribution..."
npx snarkjs zkey contribute build/keys/main_0001.zkey build/keys/main_0002.zkey \
    --name="Circuit contribution 2" -v -e="$(openssl rand -hex 32)"

# Apply random beacon to finalize
echo "   Finalizing circuit setup..."
npx snarkjs zkey beacon build/keys/main_0002.zkey build/keys/main_final.zkey \
    0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon phase2"

# Export verification key
echo "   Exporting verification key..."
npx snarkjs zkey export verificationkey build/keys/main_final.zkey build/keys/verification_key.json

# Verify the final zkey
echo "   Verifying final setup..."
npx snarkjs zkey verify build/circuits/main_c.r1cs build/keys/pot${POWER}_final.ptau build/keys/main_final.zkey

# Generate Solidity verifier contract (optional)
echo "   Generating Solidity verifier..."
npx snarkjs zkey export solidityverifier build/keys/main_final.zkey build/contracts/verifier.sol

# Clean up intermediate files to save space
echo "🧹 Cleaning up intermediate files..."
rm -f build/keys/pot${POWER}_0000.ptau
rm -f build/keys/pot${POWER}_0001.ptau
rm -f build/keys/pot${POWER}_0002.ptau
rm -f build/keys/pot${POWER}_beacon.ptau
rm -f build/keys/main_0000.zkey
rm -f build/keys/main_0001.zkey
rm -f build/keys/main_0002.zkey

echo "✅ Trusted setup complete!"
echo ""
echo "🔑 Generated files:"
echo "   Final powers of tau: build/keys/pot${POWER}_final.ptau"
echo "   Proving key: build/keys/main_final.zkey"
echo "   Verification key: build/keys/verification_key.json"
echo "   Solidity verifier: build/contracts/verifier.sol"
echo ""

# Display key information
echo "🔍 Setup information:"
if [ -f "build/keys/verification_key.json" ]; then
    echo "   Verification key size: $(wc -c < build/keys/verification_key.json) bytes"
fi
if [ -f "build/keys/main_final.zkey" ]; then
    echo "   Proving key size: $(du -h build/keys/main_final.zkey | cut -f1)"
fi

echo ""
echo "⚠️  SECURITY WARNING:"
echo "   This is a testing setup only!"
echo "   For production use:"
echo "   1. Use a larger power of tau ceremony"
echo "   2. Participate in or download an existing trusted ceremony"
echo "   3. Contribute with secure randomness"
echo "   4. Verify all ceremony files"
echo ""
echo "🎯 Next steps:"
echo "   1. Run tests: npm test"
echo "   2. Generate proofs: npm run prove"
echo "   3. Verify proofs: node scripts/verify.js"
