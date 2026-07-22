//! libFuzzer target testing DNS domain name string parsing and normalization.

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::str::FromStr;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = hickory_proto::rr::Name::from_str(s);
        let normalized = kinetic_core::types::normalize_name(s);
        let _ = kinetic_core::types::extract_apex_domain(&normalized);
    }
});
