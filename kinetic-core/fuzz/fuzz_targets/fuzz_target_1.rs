#![no_main]
use libfuzzer_sys::fuzz_target;
use kinetic_core::types::{Reveal, Heartbeat, Commitment};

fuzz_target!(|data: &[u8]| {
    // Fuzz the parsing logic that KineticRecordStore uses
    if let Ok(_reveal) = serde_json::from_slice::<Reveal>(data) {
        // Successfully parsed as Reveal
    } else if let Ok(_heartbeat) = serde_json::from_slice::<Heartbeat>(data) {
        // Successfully parsed as Heartbeat
    } else if let Ok(_commitment) = serde_json::from_slice::<Commitment>(data) {
        // Successfully parsed as Commitment
    }
});
