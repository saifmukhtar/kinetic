use kinetic_core::traits::VdfEngine;
use kinetic_core::types::Commitment;
use kinetic_vdf::ChiaVdfEngine;
use std::fs::File;
use std::thread;
use std::time::Duration;

#[test]
fn test_005_cpu_starvation_race() {
    let engine1 = ChiaVdfEngine::new();
    let challenge = Commitment { hash: [1u8; 32] };

    // Thread 1 evaluates
    let handle = thread::spawn(move || {
        engine1.evaluate(&challenge, 10_000).unwrap();
    });

    // Give thread 1 a moment to start and acquire the lock
    thread::sleep(Duration::from_millis(50));

    // The main thread tries to acquire the lock non-blocking
    let lock_path = std::env::temp_dir().join("kinetic_vdf.lock");
    // Ensure the file exists
    let lock_file = File::create(&lock_path).unwrap();

    use fs2::FileExt;

    // Under OLD logic, the lock didn't exist, so this would succeed and we'd thrash CPU
    // Under NEW logic, this should fail with a WouldBlock error because Thread 1 has the exclusive lock!
    let try_lock = lock_file.try_lock_exclusive();

    assert!(
        try_lock.is_err(),
        "SECURITY FLAW: VDF engine did not acquire a system-wide exclusive lock, leaving the CPU vulnerable to starvation!"
    );

    handle.join().unwrap();
}
