#![no_main]

use libfuzzer_sys::fuzz_target;
use kinetic_kid::{KidDocument, CapabilityManifest};
use std::str;

fuzz_target!(|data: &[u8]| {
    if let Ok(json_str) = str::from_utf8(data) {
        // Try parsing as KidDocument
        let _ = serde_json::from_str::<KidDocument>(json_str);
        
        // Try parsing as CapabilityManifest
        let _ = serde_json::from_str::<CapabilityManifest>(json_str);
    }
});
