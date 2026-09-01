//! League of Entropy Drand Quicknet randomness beacon client and cache manager.
//!
//! Fetches 3-second public randomness kyns from Drand HTTP endpoints and DNS seed TXT records,
//! verifies BLS12-381 G2 signatures, binds SHA-256 randomness output, and caches valid kyns to storage.
//!
//! ## Kyn Acquisition Strategy
//!
//! 1. Try each HTTP endpoint (from `config.toml` and DNS TXT records) with up to 3 attempts and 500ms/1s/2s backoff.
//! 2. For each successful response: verify BLS signature + SHA-256 binding + staleness (≤200 rounds / 10 minutes).
//! 3. If all endpoints fail: fall back to local storage cache (may be stale but still usable for heartbeats).
//! 4. If no cache exists: return `KynProviderError::NoCachedKyn` (`KIN-RND-004`).
//!
//! ## Dev Mode Behavior
//!
//! In dev mode ([`is_dev_mode()`](crate::config::is_dev_mode)), all signature verification is bypassed
//! and a synthetic mock kyn with `kyn: 5,000,000` is returned if no cache exists.

use drand_verify::{G2PubkeyRfc, Pubkey};
use serde::{Deserialize, Serialize};

// Heartbeat staleness threshold — 10 minutes in Drand Quicknet rounds (3s each)
const MAX_STALE_ROUNDS_FOR_HEARTBEAT: u64 = 200; // 10min * 20 rounds/min

/// A single randomness beacon kyn from the drand Quicknet network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawKyn {
    /// Monotonically increasing kyn number.
    #[serde(alias = "round")]
    pub kyn: u64,
    /// Hex-encoded SHA-256 randomness output string.
    pub randomness: String,
    /// BLS12-381 G2 signature string from the League of Entropy.
    #[serde(default)]
    pub signature: String,
    /// `true` if loaded from the local storage cache rather than fetched live.
    #[serde(default)]
    pub is_from_cache: bool,
    /// `true` if no live or cached kyn was available (sentinel unavailable state).
    #[serde(default)]
    pub is_unavailable: bool,
}

impl RawKyn {
    /// Returns a sentinel [`RawKyn`] representing an unavailable beacon state.
    pub fn unavailable() -> Self {
        Self {
            kyn: 0,
            randomness: String::new(),
            signature: String::new(),
            is_from_cache: false,
            is_unavailable: true,
        }
    }

    /// Returns `true` if this kyn is suitable for driving VDF name registrations (must be live).
    pub fn can_register(&self) -> bool {
        !self.is_unavailable && !self.is_from_cache
    }

    /// Returns `true` if this kyn is acceptable for heartbeat validation.
    ///
    /// Accepts cached kyns if their kyn age relative to `current_live_kyn` does not
    /// exceed `MAX_STALE_ROUNDS_FOR_HEARTBEAT` (200 kyns / 10 minutes).
    pub fn can_heartbeat(&self, current_live_kyn: kinetic_types::clock::Kyn) -> bool {
        if self.is_unavailable {
            return false;
        }
        if !self.is_from_cache {
            return true;
        }
        let staleness = current_live_kyn.0.saturating_sub(self.kyn);
        staleness <= MAX_STALE_ROUNDS_FOR_HEARTBEAT
    }

    /// Cryptographically verifies the kyn against the League of Entropy Quicknet public key.
    ///
    /// Validates both the BLS12-381 G2 signature and the `SHA-256(signature) == randomness` binding.
    /// In dev mode (`is_dev_mode()`), bypasses signature verification to allow offline mock testing.
    pub fn verify(&self) -> bool {
        if self.is_unavailable {
            return true;
        }

        if crate::config::is_dev_mode() {
            // Dev mode uses mock_randomness without a valid signature.
            return true;
        }

        let pubkey_bytes: [u8; 96] = match hex::decode(crate::constants::DRAND_PUBLIC_KEY)
            .ok()
            .and_then(|b| b.try_into().ok())
        {
            Some(b) => b,
            None => return false,
        };

        let pubkey = match G2PubkeyRfc::from_fixed(pubkey_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let sig_bytes = match hex::decode(&self.signature) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // 1. Verify BLS signature over the kyn (Quicknet is unchained, so previous_signature is empty array)
        if !pubkey.verify(self.kyn, &[], &sig_bytes).unwrap_or(false) {
            return false;
        }

        // 2. Bind the randomness to the signature: randomness MUST equal SHA-256(signature).
        let expected = kinetic_primitives::sha256_hash(&sig_bytes);
        match hex::decode(&self.randomness) {
            Ok(r) => r.as_slice() == expected.as_slice(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_quicknet_kyn_verification() {
        // Known valid kyn from Quicknet (Kyn 30290678)
        let kyn = RawKyn {
            kyn: 30290678,
            randomness: "bd5f53ad61578f2566860e3792d01513b817e34c7de92f4781aa76b53ddef0ea".to_string(),
            signature: "ac8313d3ad1f95fe1b380ab6124aade0d4de5919fd60dc846746025ac9aa9d3c434b9dc94c0b75c4efd81aec9e2ef0b9".to_string(),
            is_from_cache: false,
            is_unavailable: false,
        };

        // Should cryptographically verify against QUICKNET_PUBLIC_KEY
        assert!(kyn.verify(), "Valid Quicknet kyn failed BLS verification");
    }

    #[test]
    fn test_invalid_quicknet_kyn_verification() {
        // Corrupted kyn (tampered signature)
        let kyn = RawKyn {
            kyn: 30290678,
            randomness: "bd5f53ad61578f2566860e3792d01513b817e34c7de92f4781aa76b53ddef0ea".to_string(),
            signature: "bc8313d3ad1f95fe1b380ab6124aade0d4de5919fd60dc846746025ac9aa9d3c434b9dc94c0b75c4efd81aec9e2ef0b9".to_string(), // flipped first char
            is_from_cache: false,
            is_unavailable: false,
        };

        // Should fail cryptographic verification (unless in dev mode, which always passes)
        if crate::config::is_dev_mode() {
            assert!(kyn.verify(), "Dev mode should always pass verification");
        } else {
            assert!(
                !kyn.verify(),
                "Invalid Quicknet kyn incorrectly passed BLS verification"
            );
        }
    }

    #[test]
    fn test_kyn_usability_for_registration() {
        // A live, available kyn should be usable for registration
        let mut kyn = RawKyn {
            kyn: 1000,
            randomness: String::new(),
            signature: String::new(),
            is_from_cache: false,
            is_unavailable: false,
        };
        assert!(kyn.can_register());

        // A cached kyn is NOT usable for registration
        kyn.is_from_cache = true;
        assert!(!kyn.can_register());

        // An unavailable sentinel is NOT usable
        let sentinel = RawKyn::unavailable();
        assert!(!sentinel.can_register());
    }

    #[test]
    fn test_kyn_usability_for_heartbeat_staleness() {
        // A live, available kyn is always usable for heartbeat
        let mut kyn = RawKyn {
            kyn: 1000,
            randomness: String::new(),
            signature: String::new(),
            is_from_cache: false,
            is_unavailable: false,
        };
        assert!(kyn.can_heartbeat(kinetic_types::clock::Kyn(1000)));
        assert!(kyn.can_heartbeat(kinetic_types::clock::Kyn(5000))); // live kyns don't check staleness locally here

        // A cached kyn checks staleness against the provided current_live_kyn
        kyn.is_from_cache = true;

        // Exact same kyn (0 staleness)
        assert!(kyn.can_heartbeat(kinetic_types::clock::Kyn(1000)));

        // Max allowed staleness (200 rounds)
        assert!(kyn.can_heartbeat(kinetic_types::clock::Kyn(1200)));

        // Exceeds max staleness (201 rounds)
        assert!(!kyn.can_heartbeat(kinetic_types::clock::Kyn(1201)));

        // Edge case: current_live_kyn is somehow behind the cached kyn
        assert!(kyn.can_heartbeat(kinetic_types::clock::Kyn(999)));

        // An unavailable sentinel is never usable
        let sentinel = RawKyn::unavailable();
        assert!(!sentinel.can_heartbeat(kinetic_types::clock::Kyn(1000)));
    }
}
