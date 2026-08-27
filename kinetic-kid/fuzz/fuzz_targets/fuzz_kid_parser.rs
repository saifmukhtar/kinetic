#![no_main]

use libfuzzer_sys::fuzz_target;
use kinetic_kid::{Document, Manifest};
use std::str;

fuzz_target!(|data: &[u8]| {
    if let Ok(json_str) = str::from_utf8(data) {
        // Try parsing as Document
        let _ = serde_json::from_str::<Document>(json_str);
        
        // Try parsing as Manifest
        let _ = serde_json::from_str::<Manifest>(json_str);
    }
});
