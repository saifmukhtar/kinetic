//! libFuzzer target testing `ChiaVdfEngine::verify` against arbitrary proof byte streams and malformed FFI inputs.

#![no_main]

use libfuzzer_sys::fuzz_target;
use kinetic_vdf::ChiaVdfEngine;
use kinetic_core::traits::VdfEngine;
use kinetic_core::types::{Commitment, VdfProof};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    
    // Split the data into a 32-byte challenge and a variable-length proof.
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[0..32]);
    let challenge = Commitment { hash };
    
    // Pass the rest of the bytes as proof_bytes to test how the C++ layer 
    // handles huge arrays, small arrays, and random garbage.
    let proof = VdfProof {
        proof_bytes: data[32..].to_vec(),
    };
    
    let engine = ChiaVdfEngine::new();
    
    // The iterations count doesn't matter as much for memory safety of the parser, 
    // but 1000 is a standard small value.
    let _ = engine.verify(&challenge, &proof, 1000);
});
