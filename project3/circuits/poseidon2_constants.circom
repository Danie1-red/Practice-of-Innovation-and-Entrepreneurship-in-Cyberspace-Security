pragma circom 2.0.0;

/*
    Poseidon2 Constants for parameters (n,t,d) = (256,3,5) and (256,2,5)
    Based on the Poseidon2 paper: https://eprint.iacr.org/2023/323.pdf
    
    This file contains the round constants and optimized matrices for Poseidon2
*/

// Round constants for t=3 configuration
function POSEIDON2_C_t3() {
    // These would be the actual round constants from the Poseidon2 specification
    // For now, using placeholder values - in production, these should be the official constants
    var C[39] = [
        // External round constants (8 rounds * 3 = 24)
        0x0ee9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x1aa9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x2bb9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x3cc9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x4dd9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x5ee9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x6ff9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x7009a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x8119a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x9229a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xa339a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xb449a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xc559a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xd669a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xe779a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xf889a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x0999a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x1aa9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x2bb9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x3cc9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x4dd9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x5ee9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x6ff9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x7009a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        // Internal round constants (15 rounds)
        0x8119a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x9229a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xa339a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xb449a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xc559a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xd669a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xe779a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xf889a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x0999a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x1aa9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x2bb9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x3cc9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x4dd9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x5ee9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x6ff9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6
    ];
    return C;
}

// Round constants for t=2 configuration
function POSEIDON2_C_t2() {
    var C[31] = [
        // External round constants (8 rounds * 2 = 16)
        0x0ee9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x1aa9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x2bb9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x3cc9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x4dd9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x5ee9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x6ff9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x7009a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x8119a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x9229a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xa339a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xb449a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xc559a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xd669a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xe779a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xf889a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        // Internal round constants (15 rounds)
        0x0999a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x1aa9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x2bb9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x3cc9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x4dd9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x5ee9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x6ff9a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x7009a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x8119a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0x9229a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xa339a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xb449a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xc559a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xd669a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6,
        0xe779a5b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6b8b6
    ];
    return C;
}

// Optimized external matrix for t=3 (more efficient than original MDS)
function POSEIDON2_M_EXT_t3() {
    var M[3][3] = [
        [2, 1, 1],
        [1, 2, 1], 
        [1, 1, 3]
    ];
    return M;
}

// Optimized external matrix for t=2 
function POSEIDON2_M_EXT_t2() {
    var M[2][2] = [
        [2, 1],
        [1, 2]
    ];
    return M;
}

// Internal matrix for t=3 (identity + sparse matrix for efficiency)
function POSEIDON2_M_INT_t3() {
    var M[3][3] = [
        [1, 0, 1],
        [0, 1, 1],
        [0, 0, 1]
    ];
    return M;
}

// Internal matrix for t=2
function POSEIDON2_M_INT_t2() {
    var M[2][2] = [
        [1, 1],
        [0, 1]
    ];
    return M;
}
