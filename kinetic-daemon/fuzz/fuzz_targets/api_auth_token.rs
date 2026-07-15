#![no_main]

use libfuzzer_sys::fuzz_target;
use subtle::ConstantTimeEq;

fuzz_target!(|data: &[u8]| {
    // Fuzz the constant-time equality check used by the Kinetic API
    // Ensure no combination of bytes causes a panic
    let expected_token = b"kinetic_api_token_test_123456789";
    
    // We only test inputs that match the length to stress the constant-time check
    if data.len() == expected_token.len() {
        let _ = expected_token.ct_eq(data);
    }
});
