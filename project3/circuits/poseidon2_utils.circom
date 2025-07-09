pragma circom 2.0.0;

include "poseidon2_constants.circom";

// S-box: x^5 over the field
template Poseidon2Sbox() {
    signal input in;
    signal output out;
    
    signal in2;
    signal in4;
    
    in2 <== in * in;
    in4 <== in2 * in2;
    out <== in4 * in;
}

// External linear layer with optimized matrix
template Poseidon2ExternalLinear(t) {
    signal input in[t];
    signal output out[t];
    
    if (t == 2) {
        // Optimized matrix for t=2: [[2,1],[1,2]]
        out[0] <== 2 * in[0] + in[1];
        out[1] <== in[0] + 2 * in[1];
    } else if (t == 3) {
        // Optimized matrix for t=3: [[2,1,1],[1,2,1],[1,1,3]]
        out[0] <== 2 * in[0] + in[1] + in[2];
        out[1] <== in[0] + 2 * in[1] + in[2];
        out[2] <== in[0] + in[1] + 3 * in[2];
    }
}

// Internal linear layer (optimized for partial rounds)
template Poseidon2InternalLinear(t) {
    signal input in[t];
    signal output out[t];
    
    if (t == 2) {
        // For t=2: simple linear transformation
        out[0] <== in[0] + in[1];
        out[1] <== in[0] + 2 * in[1];
    } else if (t == 3) {
        // For t=3: optimized internal matrix
        out[0] <== in[0] + in[1];
        out[1] <== in[0] + in[1] + in[2];
        out[2] <== in[1] + 2 * in[2];
    }
}

// Simplified Poseidon2 permutation
template Poseidon2Permutation(t) {
    signal input in[t];
    signal output out[t];
    
    // Round parameters
    var nRoundsF = 8;  // Full rounds
    var nRoundsP;      // Partial rounds
    if (t == 2) {
        nRoundsP = 56;
    } else if (t == 3) {
        nRoundsP = 57;
    }
    
    var totalRounds = nRoundsF + nRoundsP;
    
    // Get constants
    var C_ext[nRoundsF * t];
    var C_int[nRoundsP];
    
    if (t == 2) {
        var C_all[31] = POSEIDON2_C_t2();
        for (var i = 0; i < 16; i++) {
            C_ext[i] = C_all[i];
        }
        for (var i = 0; i < 56; i++) {
            if (i < 15) {
                C_int[i] = C_all[16 + i];
            } else {
                C_int[i] = 0; // Pad with zeros if needed
            }
        }
    } else if (t == 3) {
        var C_all[81] = POSEIDON2_C_t3();
        for (var i = 0; i < 24; i++) {
            C_ext[i] = C_all[i];
        }
        for (var i = 0; i < 57; i++) {
            if (i < 57) {
                C_int[i] = C_all[24 + i];
            } else {
                C_int[i] = 0;
            }
        }
    }
    
    // Pre-declare all components
    component sboxExt1[nRoundsF/2][t];
    component sboxExt2[nRoundsF/2][t];
    component sboxInt[nRoundsP];
    component extLinear1[nRoundsF/2];
    component extLinear2[nRoundsF/2];
    component intLinear[nRoundsP];
    
    // Initialize all external linear components
    for (var r = 0; r < nRoundsF/2; r++) {
        extLinear1[r] = Poseidon2ExternalLinear(t);
        extLinear2[r] = Poseidon2ExternalLinear(t);
        for (var i = 0; i < t; i++) {
            sboxExt1[r][i] = Poseidon2Sbox();
            sboxExt2[r][i] = Poseidon2Sbox();
        }
    }
    
    // Initialize all internal components
    for (var r = 0; r < nRoundsP; r++) {
        sboxInt[r] = Poseidon2Sbox();
        intLinear[r] = Poseidon2InternalLinear(t);
    }
    
    // State array
    signal state[totalRounds + 1][t];
    
    // Initialize state
    for (var i = 0; i < t; i++) {
        state[0][i] <== in[i];
    }
    
    var round = 0;
    
    // First half of external rounds (4 rounds)
    for (var r = 0; r < nRoundsF / 2; r++) {
        // Add round constants and apply S-box
        for (var i = 0; i < t; i++) {
            sboxExt1[r][i].in <== state[round][i] + C_ext[r * t + i];
            extLinear1[r].in[i] <== sboxExt1[r][i].out;
        }
        
        // Apply external linear layer
        for (var i = 0; i < t; i++) {
            state[round + 1][i] <== extLinear1[r].out[i];
        }
        round++;
    }
    
    // Internal rounds (partial rounds)
    for (var r = 0; r < nRoundsP; r++) {
        // Add round constant and apply S-box only to first element
        sboxInt[r].in <== state[round][0] + C_int[r];
        intLinear[r].in[0] <== sboxInt[r].out;
        
        // Copy other elements unchanged
        for (var i = 1; i < t; i++) {
            intLinear[r].in[i] <== state[round][i];
        }
        
        // Apply internal linear layer
        for (var i = 0; i < t; i++) {
            state[round + 1][i] <== intLinear[r].out[i];
        }
        round++;
    }
    
    // Second half of external rounds (4 rounds)
    for (var r = 0; r < nRoundsF / 2; r++) {
        var round_offset = nRoundsF / 2;
        
        // Add round constants and apply S-box
        for (var i = 0; i < t; i++) {
            sboxExt2[r][i].in <== state[round][i] + C_ext[(round_offset + r) * t + i];
            extLinear2[r].in[i] <== sboxExt2[r][i].out;
        }
        
        // Apply external linear layer
        for (var i = 0; i < t; i++) {
            state[round + 1][i] <== extLinear2[r].out[i];
        }
        round++;
    }
    
    // Output final state
    for (var i = 0; i < t; i++) {
        out[i] <== state[totalRounds][i];
    }
}
