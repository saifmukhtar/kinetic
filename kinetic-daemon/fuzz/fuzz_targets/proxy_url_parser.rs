#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Attempt to parse arbitrary URLs through the HTTP proxy router
        // This ensures reqwest or hyper URL processing doesn't crash on garbage inputs
        let _ = reqwest::Url::parse(s);
        
        if s.contains("http") {
            let _ = reqwest::Url::parse(&format!("http://{}", s));
            let _ = reqwest::Url::parse(&format!("https://{}", s));
        }
    }
});
