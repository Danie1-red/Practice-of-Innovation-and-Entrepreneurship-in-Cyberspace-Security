pragma circom 2.0.0;

include "poseidon2.circom";

/*
    Simple test circuit for Poseidon2 hash function
    Used for basic functionality testing
*/

template Poseidon2Test_t2() {
    signal input in;
    signal output out;
    
    component hash = Poseidon2_t2();
    hash.in <== in;
    out <== hash.out;
}

template Poseidon2Test_t3() {
    signal input in[2];
    signal output out;
    
    component hash = Poseidon2_t3();
    hash.in[0] <== in[0];
    hash.in[1] <== in[1];
    out <== hash.out;
}

// Test with t=2
component main = Poseidon2Test_t2();
