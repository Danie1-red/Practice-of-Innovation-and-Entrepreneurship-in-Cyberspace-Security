pragma circom 2.0.0;

include "poseidon2_constants.circom";
include "poseidon2_utils.circom";

/*
    Poseidon2 Hash Function Implementation
    
    Based on the paper: "Poseidon2: A Faster Version of the Poseidon Hash Function"
    https://eprint.iacr.org/2023/323.pdf
    
    Supports both compression function and sponge modes
    Parameters: (n,t,d) = (256,3,5) or (256,2,5)
*/

// Poseidon2 in compression mode (fixed input size)
template Poseidon2Compression(t) {
    signal input in[t-1];  // t-1 inputs (one slot reserved for capacity)
    signal output out;
    
    component perm = Poseidon2Permutation(t);
    
    // Initialize state: inputs + zero capacity
    for (var i = 0; i < t-1; i++) {
        perm.in[i] <== in[i];
    }
    perm.in[t-1] <== 0;  // Capacity element
    
    // Output is the first element of the permuted state
    out <== perm.out[0];
}

// Poseidon2 in sponge mode (variable input size)
template Poseidon2Sponge(nInputs, t) {
    signal input in[nInputs];
    signal output out;
    
    // Calculate number of absorption phases
    var rate = t - 1;  // Rate = t - capacity (capacity = 1)
    var nBlocks = (nInputs + rate - 1) \ rate;  // Ceiling division
    
    // Pad input to multiple of rate
    signal padded[nBlocks * rate];
    for (var i = 0; i < nInputs; i++) {
        padded[i] <== in[i];
    }
    // Pad with zeros
    for (var i = nInputs; i < nBlocks * rate; i++) {
        padded[i] <== 0;
    }
    
    // State array
    signal state[nBlocks + 1][t];
    
    // Initialize state to all zeros
    for (var i = 0; i < t; i++) {
        state[0][i] <== 0;
    }
    
    component perms[nBlocks];
    
    // Absorption phase
    for (var block = 0; block < nBlocks; block++) {
        perms[block] = Poseidon2Permutation(t);
        
        // XOR input block with state (rate part only)
        for (var i = 0; i < rate; i++) {
            perms[block].in[i] <== state[block][i] + padded[block * rate + i];
        }
        // Capacity part unchanged
        perms[block].in[t-1] <== state[block][t-1];
        
        // Update state
        for (var i = 0; i < t; i++) {
            state[block + 1][i] <== perms[block].out[i];
        }
    }
    
    // Squeezing phase (output first element)
    out <== state[nBlocks][0];
}

// Main Poseidon2 hash function with configurable parameters
template Poseidon2(nInputs, t) {
    signal input in[nInputs];
    signal output out;
    
    if (nInputs == t - 1) {
        // Use compression mode for exactly t-1 inputs
        component comp = Poseidon2Compression(t);
        for (var i = 0; i < nInputs; i++) {
            comp.in[i] <== in[i];
        }
        out <== comp.out;
    } else {
        // Use sponge mode for other input sizes
        component sponge = Poseidon2Sponge(nInputs, t);
        for (var i = 0; i < nInputs; i++) {
            sponge.in[i] <== in[i];
        }
        out <== sponge.out;
    }
}

// Convenient wrappers for specific configurations

// Poseidon2 with t=2 (1 input)
template Poseidon2_t2() {
    signal input in;
    signal output out;
    
    component hash = Poseidon2(1, 2);
    hash.in[0] <== in;
    out <== hash.out;
}

// Poseidon2 with t=3 (2 inputs)
template Poseidon2_t3() {
    signal input in[2];
    signal output out;
    
    component hash = Poseidon2(2, 3);
    hash.in[0] <== in[0];
    hash.in[1] <== in[1];
    out <== hash.out;
}

// Poseidon2 with t=3 (1 input, padded)
template Poseidon2_t3_single() {
    signal input in;
    signal output out;
    
    component hash = Poseidon2(1, 3);
    hash.in[0] <== in;
    out <== hash.out;
}
