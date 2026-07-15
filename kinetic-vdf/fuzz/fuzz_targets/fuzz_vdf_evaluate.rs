#![no_main]

use libfuzzer_sys::fuzz_target;
use kinetic_vdf::ChiaVdfEngine;
use kinetic_core::traits::VdfEngine;
use kinetic_core::types::Commitment;

fuzz_target!(|data: &[u8]| {
    if data.len() < 40 {
        return;
    }
    
    // First 32 bytes for the challenge hash
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[0..32]);
    let challenge = Commitment { hash };
    
    // Next 8 bytes for iterations (capped to a small number for fuzzing speed)
    let mut iter_bytes = [0u8; 8];
    iter_bytes.copy_from_slice(&data[32..40]);
    let mut iterations = u64::from_le_bytes(iter_bytes) % 1000;
    
    // 0 iterations is an edge case we want to test!
    
    let engine = ChiaVdfEngine::new();
    
    // We want to test evaluate(), which acquires the lock and calls C++ prove()
    let _ = engine.evaluate(&challenge, iterations);
});
