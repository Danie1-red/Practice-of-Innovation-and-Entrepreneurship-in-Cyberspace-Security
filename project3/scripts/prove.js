const snarkjs = require("snarkjs");
const fs = require("fs");
const path = require("path");

/**
 * Poseidon2 Proof Generation Script (Simplified)
 * Uses snarkjs groth16 fullprove for easier proof generation
 */

async function generateProof() {
    console.log("🔐 Generating Groth16 proof for Poseidon2 preimage...");

    try {
        // Check if required files exist
        const wasmPath = "build/wasm/main_c.wasm";
        const zkeyPath = "build/keys/main_final.zkey";

        if (!fs.existsSync(wasmPath)) {
            throw new Error("WASM file not found. Run ./scripts/compile.sh first");
        }
        if (!fs.existsSync(zkeyPath)) {
            throw new Error("Proving key not found. Run ./scripts/setup.sh first");
        }

        // Example input: prove knowledge of preimage that hashes to specific value
        const preimage = "12345"; // Secret preimage
        
        console.log("📊 Computing expected hash first...");
        
        // First compute the hash using the test circuit
        const testInput = { in: preimage };
        const testWasm = "build/wasm/test_poseidon2.wasm";
        
        if (!fs.existsSync(testWasm)) {
            throw new Error("Test WASM file not found. Run ./scripts/compile.sh first");
        }
        
        // Use snarkjs CLI to compute hash
        fs.writeFileSync("temp_test_input.json", JSON.stringify(testInput));
        
        const { exec } = require('child_process');
        const util = require('util');
        const execPromise = util.promisify(exec);
        
        console.log("   Computing hash using test circuit...");
        await execPromise('npx snarkjs wtns calculate build/wasm/test_poseidon2.wasm temp_test_input.json temp_test_witness.wtns');
        await execPromise('npx snarkjs wtns export json temp_test_witness.wtns temp_test_witness.json');
        
        const testWitness = JSON.parse(fs.readFileSync('temp_test_witness.json'));
        const expectedHash = testWitness[1];
        console.log("   Expected hash:", expectedHash);
        
        // Now create the main circuit input
        const input = {
            hash: expectedHash,      // Public input
            preimage: preimage       // Private input
        };
        
        console.log("🏗️  Generating proof using fullprove...");
        
        // Create outputs directory
        const outputDir = "build/proofs";
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }
        
        // Save input
        const inputPath = path.join(outputDir, "input.json");
        fs.writeFileSync(inputPath, JSON.stringify(input, null, 2));
        
        const startTime = Date.now();
        
        // Use groth16 fullprove - this does everything in one step
        const proofPath = path.join(outputDir, "proof.json");
        const publicPath = path.join(outputDir, "public.json");
        
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            wasmPath,
            zkeyPath
        );
        
        const endTime = Date.now();
        console.log(`⏱️  Proof generation time: ${endTime - startTime}ms`);
        
        // Save proof and public signals
        fs.writeFileSync(proofPath, JSON.stringify(proof, null, 2));
        fs.writeFileSync(publicPath, JSON.stringify(publicSignals, null, 2));
        
        console.log("✅ Proof generated successfully!");
        console.log("");
        console.log("📋 Proof Details:");
        console.log("   Public signals:", publicSignals);
        console.log("   Proof size:", JSON.stringify(proof).length, "bytes");
        console.log("");
        console.log("📁 Generated files:");
        console.log("   Proof: build/proofs/proof.json");
        console.log("   Public signals: build/proofs/public.json");
        console.log("   Input: build/proofs/input.json");
        
        // Verify the proof
        console.log("🔍 Verifying proof...");
        await verifyProof();
        
        // Cleanup temporary files
        fs.unlinkSync('temp_test_input.json');
        fs.unlinkSync('temp_test_witness.wtns');
        fs.unlinkSync('temp_test_witness.json');
        
    } catch (error) {
        console.error("❌ Error generating proof:", error.message);
        process.exit(1);
    }
}

async function verifyProof() {
    try {
        const vkeyPath = "build/keys/verification_key.json";
        const proofPath = "build/proofs/proof.json";
        const publicPath = "build/proofs/public.json";
        
        if (!fs.existsSync(vkeyPath) || !fs.existsSync(proofPath) || !fs.existsSync(publicPath)) {
            throw new Error("Verification files not found");
        }
        
        const vKey = JSON.parse(fs.readFileSync(vkeyPath));
        const proof = JSON.parse(fs.readFileSync(proofPath));
        const publicSignals = JSON.parse(fs.readFileSync(publicPath));
        
        const startTime = Date.now();
        const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);
        const endTime = Date.now();
        
        console.log(`⏱️  Verification time: ${endTime - startTime}ms`);
        
        if (res === true) {
            console.log("✅ Proof verification: VALID");
        } else {
            console.log("❌ Proof verification: INVALID");
        }
        
        return res;
        
    } catch (error) {
        console.error("❌ Error verifying proof:", error.message);
        return false;
    }
}

// Main execution
async function main() {
    const args = process.argv.slice(2);
    
    if (args.includes("--verify-only")) {
        await verifyProof();
    } else {
        await generateProof();
    }
}

// Handle script execution
if (require.main === module) {
    main().catch(error => {
        console.error("Fatal error:", error);
        process.exit(1);
    });
}

module.exports = {
    generateProof,
    verifyProof
};
