const chai = require("chai");
const path = require("path");
const wasm_tester = require("circom_tester").wasm;
const F = require("ffjavascript").F1Field;
const Scalar = require("ffjavascript").Scalar;

const assert = chai.assert;

// Field for BN128
const p = Scalar.fromString("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const Fr = new F(p);

describe("Poseidon2 Hash Function Test", function () {
    this.timeout(100000);

    let circuit_t2, circuit_t3, main_circuit;

    before(async () => {
        // Compile test circuits
        circuit_t2 = await wasm_tester(path.join(__dirname, "../circuits", "test_poseidon2.circom"));
        
        // Compile main circuit
        main_circuit = await wasm_tester(path.join(__dirname, "../circuits", "main.circom"));
    });

    it("Should compute Poseidon2 hash with t=2", async () => {
        const input = {
            in: "123"
        };

        const witness = await circuit_t2.calculateWitness(input, true);
        
        // Check that we have a valid witness
        assert.equal(witness.length > 0, true);
        
        // The output should be in witness[1] (after public signal)
        const output = Fr.toString(witness[1]);
        console.log("Poseidon2 t=2 hash output:", output);
        
        // Basic sanity checks
        assert.notEqual(output, "0");
        assert.notEqual(output, input.in);
    });

    it("Should verify preimage proof with t=2", async () => {
        const preimage = "12345";
        
        // First, compute the hash
        const hashInput = {
            in: preimage
        };
        
        const hashWitness = await circuit_t2.calculateWitness(hashInput, true);
        const expectedHash = Fr.toString(hashWitness[1]);
        
        console.log("Expected hash:", expectedHash);
        console.log("Preimage:", preimage);
        
        // Now verify the preimage proof
        const proofInput = {
            hash: expectedHash,
            preimage: preimage
        };
        
        const proofWitness = await main_circuit.calculateWitness(proofInput, true);
        
        // Check that the proof is valid (valid output should be 1)
        const isValid = Fr.toString(proofWitness[1]);
        console.log("Proof validity:", isValid);
        
        assert.equal(isValid, "1", "Proof should be valid");
    });

    it("Should reject invalid preimage", async () => {
        const correctPreimage = "12345";
        const wrongPreimage = "54321";
        
        // Compute hash with correct preimage
        const hashInput = {
            in: correctPreimage
        };
        
        const hashWitness = await circuit_t2.calculateWitness(hashInput, true);
        const expectedHash = Fr.toString(hashWitness[1]);
        
        // Try to prove with wrong preimage
        const proofInput = {
            hash: expectedHash,
            preimage: wrongPreimage
        };
        
        try {
            // This should fail during witness calculation due to the constraint
            const proofWitness = await main_circuit.calculateWitness(proofInput, true);
            assert.fail("Should have failed with wrong preimage");
        } catch (error) {
            console.log("Expected error with wrong preimage:", error.message);
            assert.include(error.message.toLowerCase(), "assert", "Should fail due to assertion violation");
        }
    });

    it("Should handle edge cases", async () => {
        // Test with zero input
        const zeroInput = {
            in: "0"
        };

        const witness = await circuit_t2.calculateWitness(zeroInput, true);
        const output = Fr.toString(witness[1]);
        console.log("Poseidon2 hash of 0:", output);
        
        assert.notEqual(output, "0", "Hash of zero should not be zero");

        // Test with maximum field element
        const maxInput = {
            in: p.toString()
        };

        try {
            const maxWitness = await circuit_t2.calculateWitness(maxInput, true);
            const maxOutput = Fr.toString(maxWitness[1]);
            console.log("Poseidon2 hash of max field element:", maxOutput);
        } catch (error) {
            console.log("Expected behavior with field overflow");
        }
    });

    it("Should be deterministic", async () => {
        const input = {
            in: "999999"
        };

        // Compute hash twice
        const witness1 = await circuit_t2.calculateWitness(input, true);
        const witness2 = await circuit_t2.calculateWitness(input, true);
        
        const output1 = Fr.toString(witness1[1]);
        const output2 = Fr.toString(witness2[1]);
        
        assert.equal(output1, output2, "Hash function should be deterministic");
    });
});

// Helper function to generate random field element
function randomFieldElement() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    
    let num = 0n;
    for (let i = 0; i < 32; i++) {
        num = num * 256n + BigInt(bytes[i]);
    }
    
    return Fr.toString(Fr.e(num));
}

// Performance test (optional)
describe("Poseidon2 Performance Tests", function() {
    this.timeout(30000);
    
    let circuit;
    
    before(async () => {
        circuit = await wasm_tester(path.join(__dirname, "../circuits", "test_poseidon2.circom"));
    });
    
    it("Should compute multiple hashes efficiently", async () => {
        const numTests = 10;
        const startTime = Date.now();
        
        for (let i = 0; i < numTests; i++) {
            const input = {
                in: i.toString()
            };
            
            await circuit.calculateWitness(input, true);
        }
        
        const endTime = Date.now();
        const avgTime = (endTime - startTime) / numTests;
        
        console.log(`Average time per hash: ${avgTime.toFixed(2)}ms`);
        console.log(`Total time for ${numTests} hashes: ${endTime - startTime}ms`);
        
        // Performance assertion (adjust threshold as needed)
        assert.isBelow(avgTime, 1000, "Hash computation should be reasonably fast");
    });
});
