use kinetic_core::traits::VdfEngine;
use kinetic_core::types::Commitment;
use kinetic_vdf::ChiaVdfEngine;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

#[test]
fn test_multiple_engines_independent() {
    let engine1 = ChiaVdfEngine::new();
    let engine2 = ChiaVdfEngine::new();

    let challenge = Commitment { hash: [20u8; 32] };

    let proof1 = engine1.evaluate(&challenge, 1000).unwrap();
    let is_valid = engine2.verify(&challenge, &proof1, 1000).unwrap();

    assert!(is_valid, "Engines should be interchangeable");
}

#[test]
fn test_concurrent_blocking_evaluations() {
    let num_threads = 4;
    let mut handles = vec![];
    let completed = Arc::new(Mutex::new(0));

    for i in 0..num_threads {
        let completed_clone = Arc::clone(&completed);
        let handle = thread::spawn(move || {
            let engine = ChiaVdfEngine::new();
            let challenge = Commitment {
                hash: [i as u8; 32],
            };

            // This evaluate call acquires an exclusive lock
            let start = Instant::now();
            let proof = engine.evaluate(&challenge, 5000).unwrap();
            let _dur = start.elapsed();

            let is_valid = engine.verify(&challenge, &proof, 5000).unwrap();
            assert!(is_valid);

            let mut count = completed_clone.lock().unwrap();
            *count += 1;
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let count = completed.lock().unwrap();
    assert_eq!(
        *count, num_threads,
        "All threads should complete successfully"
    );
}
