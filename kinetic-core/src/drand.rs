//! verifies BLS12-381 G2 signatures, binds SHA-256 randomness output, and caches valid kyns to storage.
//! 
//! Note: The cryptographic verification logic has been extracted to `kinetic-kyn` (Layer 1.5).

pub use kinetic_kyn::beacon::RawKyn;
