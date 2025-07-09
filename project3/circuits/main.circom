pragma circom 2.0.0;

include "poseidon2.circom";

/*
    Main circuit for Poseidon2 hash verification
    
    Public inputs: expected hash value
    Private inputs: preimage (hash input)
    
    Circuit proves knowledge of preimage that hashes to the given hash value
*/

// Main circuit for t=2 configuration (1 preimage input)
template Poseidon2PreimageProof_t2() {
    // Public input: expected hash
    signal input hash;
    
    // Private input: preimage
    signal input preimage;
    
    // Output: verification result (should be 0 if proof is valid)
    signal output valid;
    
    // Compute hash of preimage
    component poseidon2 = Poseidon2_t2();
    poseidon2.in <== preimage;
    
    // Verify hash matches expected value
    component isEqual = IsEqual();
    isEqual.in[0] <== poseidon2.out;
    isEqual.in[1] <== hash;
    
    // Output 1 if hashes match, 0 otherwise
    valid <== isEqual.out;
    
    // Constraint: hash must match (for zero-knowledge proof)
    poseidon2.out === hash;
}

// Main circuit for t=3 configuration (2 preimage inputs)
template Poseidon2PreimageProof_t3() {
    // Public input: expected hash
    signal input hash;
    
    // Private inputs: preimage parts
    signal input preimage[2];
    
    // Output: verification result
    signal output valid;
    
    // Compute hash of preimage
    component poseidon2 = Poseidon2_t3();
    poseidon2.in[0] <== preimage[0];
    poseidon2.in[1] <== preimage[1];
    
    // Verify hash matches expected value
    component isEqual = IsEqual();
    isEqual.in[0] <== poseidon2.out;
    isEqual.in[1] <== hash;
    
    valid <== isEqual.out;
    
    // Constraint: hash must match
    poseidon2.out === hash;
}

// Alternative: single input with t=3 (padded with zero)
template Poseidon2PreimageProof_t3_single() {
    // Public input: expected hash
    signal input hash;
    
    // Private input: single preimage
    signal input preimage;
    
    // Output: verification result
    signal output valid;
    
    // Compute hash of preimage (will be padded internally)
    component poseidon2 = Poseidon2_t3_single();
    poseidon2.in <== preimage;
    
    // Verify hash matches expected value
    component isEqual = IsEqual();
    isEqual.in[0] <== poseidon2.out;
    isEqual.in[1] <== hash;
    
    valid <== isEqual.out;
    
    // Constraint: hash must match
    poseidon2.out === hash;
}

// Helper template for equality check
template IsEqual() {
    signal input in[2];
    signal output out;
    
    component isz = IsZero();
    isz.in <== in[1] - in[0];
    out <== isz.out;
}

// Helper template for zero check
template IsZero() {
    signal input in;
    signal output out;
    
    signal inv;
    inv <-- in != 0 ? 1/in : 0;
    
    out <== -in*inv +1;
    in*out === 0;
}

// Choose the main component based on configuration
// For t=2 (n,t,d) = (256,2,5)
component main = Poseidon2PreimageProof_t2();

// Alternative: For t=3 (n,t,d) = (256,3,5)
// component main = Poseidon2PreimageProof_t3();

// Alternative: For t=3 with single input
// component main = Poseidon2PreimageProof_t3_single();
