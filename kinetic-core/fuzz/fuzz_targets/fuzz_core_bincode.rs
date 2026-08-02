#![no_main]

use libfuzzer_sys::fuzz_target;
use kinetic_core::types::vdf::VdfProof;
use kinetic_core::types::name_record::Heartbeat;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<VdfProof>(data);
    let _ = bincode::deserialize::<Heartbeat>(data);
});
