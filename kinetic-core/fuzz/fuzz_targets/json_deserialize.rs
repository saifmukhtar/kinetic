#![no_main]
use libfuzzer_sys::fuzz_target;
use kinetic_core::types::{Reveal, Heartbeat, Commitment};
use kinetic_core::types::dns::DnsZone;

fuzz_target!(|data: &[u8]| {
    // Fuzz the parsing logic that KineticRecordStore uses
    if let Ok(_reveal) = serde_json::from_slice::<Reveal>(data) {
        // Successfully parsed as Reveal
    } else if let Ok(_heartbeat) = serde_json::from_slice::<Heartbeat>(data) {
        // Successfully parsed as Heartbeat
    } else if let Ok(_commitment) = serde_json::from_slice::<Commitment>(data) {
        // Successfully parsed as Commitment
    } else if let Ok(_zone) = serde_json::from_slice::<DnsZone>(data) {
        // Successfully parsed as DnsZone
    }
    
    let _ = bincode::deserialize::<kinetic_core::governance::types::SignedGovernanceMessage>(data);
});
