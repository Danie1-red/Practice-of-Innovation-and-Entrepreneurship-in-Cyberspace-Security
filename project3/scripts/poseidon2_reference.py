#!/usr/bin/env python3
"""
Poseidon2 Hash Function Reference Implementation in Python

This is a reference implementation for testing and verification purposes.
Based on the paper: "Poseidon2: A Faster Version of the Poseidon Hash Function"
https://eprint.iacr.org/2023/323.pdf

Parameters: (n,t,d) = (256,3,5) or (256,2,5)
"""

import sys
from typing import List, Tuple
import json

# BN254 field modulus
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def mod_exp(base: int, exp: int, mod: int) -> int:
    """Modular exponentiation"""
    return pow(base, exp, mod)

def mod_inv(a: int, mod: int) -> int:
    """Modular inverse using extended Euclidean algorithm"""
    return mod_exp(a, mod - 2, mod)

class Poseidon2:
    """Poseidon2 hash function implementation"""
    
    def __init__(self, t: int = 3):
        """
        Initialize Poseidon2 with width t
        
        Args:
            t: Width of the permutation (2 or 3)
        """
        self.t = t
        self.n_rounds_f = 8  # External rounds
        self.n_rounds_p = 15  # Internal rounds for t=2,3 with n=256
        
        # Load constants (in practice, these should be loaded from the specification)
        self.round_constants = self._generate_round_constants()
        self.mds_matrix_ext = self._get_external_matrix()
        self.mds_matrix_int = self._get_internal_matrix()
    
    def _generate_round_constants(self) -> List[int]:
        """Generate round constants (placeholder implementation)"""
        # In practice, these should be the official constants from the specification
        constants = []
        
        # External round constants
        for i in range(self.n_rounds_f * self.t):
            # Using a simple PRNG for demonstration - replace with official constants
            constant = pow(2, 128 + i, P)
            constants.append(constant)
        
        # Internal round constants
        for i in range(self.n_rounds_p):
            constant = pow(3, 128 + self.n_rounds_f * self.t + i, P)
            constants.append(constant)
        
        return constants
    
    def _get_external_matrix(self) -> List[List[int]]:
        """Get optimized external MDS matrix"""
        if self.t == 2:
            return [
                [2, 1],
                [1, 2]
            ]
        elif self.t == 3:
            return [
                [2, 1, 1],
                [1, 2, 1],
                [1, 1, 3]
            ]
        else:
            raise ValueError(f"Unsupported width t={self.t}")
    
    def _get_internal_matrix(self) -> List[List[int]]:
        """Get sparse internal matrix for efficiency"""
        if self.t == 2:
            return [
                [1, 1],
                [0, 1]
            ]
        elif self.t == 3:
            return [
                [1, 0, 1],
                [0, 1, 1],
                [0, 0, 1]
            ]
        else:
            raise ValueError(f"Unsupported width t={self.t}")
    
    def _sbox(self, x: int) -> int:
        """S-box: x^5"""
        return mod_exp(x, 5, P)
    
    def _matrix_mult(self, matrix: List[List[int]], state: List[int]) -> List[int]:
        """Multiply state by matrix"""
        result = []
        for i in range(len(matrix)):
            val = 0
            for j in range(len(state)):
                val = (val + matrix[i][j] * state[j]) % P
            result.append(val)
        return result
    
    def _external_round(self, state: List[int], round_idx: int) -> List[int]:
        """Perform external round (full S-box + external matrix)"""
        # Add round constants
        for i in range(self.t):
            state[i] = (state[i] + self.round_constants[round_idx * self.t + i]) % P
        
        # Apply S-box to all elements
        for i in range(self.t):
            state[i] = self._sbox(state[i])
        
        # Apply external matrix
        state = self._matrix_mult(self.mds_matrix_ext, state)
        
        return state
    
    def _internal_round(self, state: List[int], round_idx: int) -> List[int]:
        """Perform internal round (single S-box + internal matrix)"""
        # Add round constant to first element only
        const_idx = self.n_rounds_f * self.t + round_idx
        state[0] = (state[0] + self.round_constants[const_idx]) % P
        
        # Apply S-box to first element only
        state[0] = self._sbox(state[0])
        
        # Apply internal matrix
        state = self._matrix_mult(self.mds_matrix_int, state)
        
        return state
    
    def permutation(self, state: List[int]) -> List[int]:
        """Apply Poseidon2 permutation"""
        if len(state) != self.t:
            raise ValueError(f"State must have length {self.t}")
        
        state = state.copy()
        
        # First half of external rounds
        for r in range(self.n_rounds_f // 2):
            state = self._external_round(state, r)
        
        # Internal rounds
        for r in range(self.n_rounds_p):
            state = self._internal_round(state, r)
        
        # Second half of external rounds
        for r in range(self.n_rounds_f // 2, self.n_rounds_f):
            state = self._external_round(state, r)
        
        return state
    
    def hash_compression(self, inputs: List[int]) -> int:
        """Hash in compression mode (fixed input size t-1)"""
        if len(inputs) != self.t - 1:
            raise ValueError(f"Compression mode requires exactly {self.t - 1} inputs")
        
        # Initialize state: inputs + zero capacity
        state = inputs + [0]
        
        # Apply permutation
        state = self.permutation(state)
        
        # Return first element
        return state[0]
    
    def hash_sponge(self, inputs: List[int]) -> int:
        """Hash in sponge mode (variable input size)"""
        rate = self.t - 1  # Rate = t - capacity (capacity = 1)
        
        # Pad inputs to multiple of rate
        padded = inputs.copy()
        while len(padded) % rate != 0:
            padded.append(0)
        
        # Initialize state
        state = [0] * self.t
        
        # Absorption phase
        for i in range(0, len(padded), rate):
            # XOR block with state (rate part only)
            for j in range(rate):
                state[j] = (state[j] + padded[i + j]) % P
            
            # Apply permutation
            state = self.permutation(state)
        
        # Squeezing phase (return first element)
        return state[0]
    
    def hash(self, inputs: List[int]) -> int:
        """Main hash function (automatically chooses mode)"""
        if len(inputs) == self.t - 1:
            return self.hash_compression(inputs)
        else:
            return self.hash_sponge(inputs)

def test_poseidon2():
    """Test Poseidon2 implementation"""
    print("🧪 Testing Poseidon2 implementation...")
    
    # Test with t=2
    p2_t2 = Poseidon2(t=2)
    
    test_input = [12345]
    hash_output = p2_t2.hash(test_input)
    print(f"Poseidon2 t=2 hash of {test_input}: {hash_output}")
    
    # Test with t=3
    p2_t3 = Poseidon2(t=3)
    
    test_input_2 = [12345, 67890]
    hash_output_2 = p2_t3.hash(test_input_2)
    print(f"Poseidon2 t=3 hash of {test_input_2}: {hash_output_2}")
    
    # Test single input with t=3 (sponge mode)
    test_input_3 = [12345]
    hash_output_3 = p2_t3.hash(test_input_3)
    print(f"Poseidon2 t=3 sponge hash of {test_input_3}: {hash_output_3}")
    
    # Test determinism
    hash_output_repeat = p2_t2.hash([12345])
    assert hash_output == hash_output_repeat, "Hash should be deterministic"
    print("✅ Determinism test passed")
    
    # Test different inputs produce different outputs
    hash_different = p2_t2.hash([54321])
    assert hash_output != hash_different, "Different inputs should produce different hashes"
    print("✅ Different inputs test passed")
    
    print("✅ All tests passed!")

def generate_test_vectors():
    """Generate test vectors for circuit verification"""
    print("📋 Generating test vectors...")
    
    test_vectors = []
    
    # Test vectors for t=2
    p2_t2 = Poseidon2(t=2)
    for i in range(5):
        input_val = i * 12345
        output_val = p2_t2.hash([input_val])
        test_vectors.append({
            "t": 2,
            "input": [input_val],
            "output": output_val
        })
    
    # Test vectors for t=3
    p2_t3 = Poseidon2(t=3)
    for i in range(5):
        input_val1 = i * 12345
        input_val2 = i * 67890
        output_val = p2_t3.hash([input_val1, input_val2])
        test_vectors.append({
            "t": 3,
            "input": [input_val1, input_val2],
            "output": output_val
        })
    
    # Save test vectors
    with open("test_vectors.json", "w") as f:
        json.dump(test_vectors, f, indent=2)
    
    print(f"📁 Generated {len(test_vectors)} test vectors -> test_vectors.json")
    
    return test_vectors

def main():
    """Main function"""
    if len(sys.argv) > 1:
        if sys.argv[1] == "test":
            test_poseidon2()
        elif sys.argv[1] == "vectors":
            generate_test_vectors()
        elif sys.argv[1] == "hash":
            if len(sys.argv) < 4:
                print("Usage: python poseidon2_reference.py hash <t> <input1> [input2]")
                sys.exit(1)
            
            t = int(sys.argv[2])
            inputs = [int(x) for x in sys.argv[3:]]
            
            p2 = Poseidon2(t=t)
            result = p2.hash(inputs)
            print(f"Hash result: {result}")
        else:
            print("Usage: python poseidon2_reference.py [test|vectors|hash]")
    else:
        test_poseidon2()
        generate_test_vectors()

if __name__ == "__main__":
    main()
