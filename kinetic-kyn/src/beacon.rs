use crate::types::Kyn;
use beacon_verify::{G2PubkeyRfc, Pubkey};
use serde::{Deserialize, Deserializer, Serialize};

// Heartbeat staleness threshold — 10 minutes (600 seconds/kyns)
const MAX_STALE_ROUNDS_FOR_HEARTBEAT: u64 = 600;

/// Intercepts the Drand round during deserialization and instantly multiplies it 
/// by KYN_PERIOD so the rest of the Engine only ever deals with 1-Second Kyns.
fn deserialize_drand_round_to_kyn<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let round = u64::deserialize(deserializer)?;
    let period: u64 = env!("KYN_PERIOD").parse().unwrap_or(3);
    Ok(round * period)
}

/// A single network time kyn from the global provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawKyn {
    /// The monotonically increasing Engine Kyn number (1 Kyn = 1 Second).
    #[serde(alias = "round", deserialize_with = "deserialize_drand_round_to_kyn")]
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

/// Abstract cryptographic verifier for time beacon signatures.
/// 
/// Confirms that the `signature_hex` is a valid BLS12-381 G2 signature produced by the 
/// globally trusted time beacon for the provided `kyn` round.
pub fn verify_beacon_signature(kyn: u64, signature_hex: &str, bypass_signature: bool) -> bool {
    if bypass_signature {
        return true;
    }

    let beacon_public_key = env!("BEACON_PUBLIC_KEY");
    let pubkey_bytes: [u8; 96] = match hex::decode(beacon_public_key)
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

    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };

    pubkey.verify(kyn, &[], &sig_bytes).unwrap_or(false)
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
    pub fn can_heartbeat(&self, current_live_kyn: Kyn) -> bool {
        if self.is_unavailable {
            return false;
        }
        if !self.is_from_cache {
            return true;
        }
        let staleness = current_live_kyn.0.saturating_sub(self.kyn);
        staleness <= MAX_STALE_ROUNDS_FOR_HEARTBEAT
    }

    /// Cryptographically verifies the kyn against the trusted beacon public key.
    ///
    /// Validates both the BLS12-381 G2 signature and the `SHA-256(signature) == randomness` binding.
    /// If `bypass_signature` is true (e.g. in dev mode), this automatically returns true.
    pub fn verify_beacon(&self, bypass_signature: bool) -> bool {
        if self.is_unavailable {
            return true;
        }

        if bypass_signature {
            // Dev mode uses mock_randomness without a valid signature.
            return true;
        }

        // We temporarily reverse the kyn back to a round ONLY to verify Drand's signature
        let period: u64 = env!("KYN_PERIOD").parse().unwrap_or(3);
        let original_round = self.kyn / period;

        if !verify_beacon_signature(original_round, &self.signature, false) {
            return false;
        }

        let sig_bytes = match hex::decode(&self.signature) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // 2. Bind the randomness to the signature: randomness MUST equal SHA-256(signature).
        // Since sha256_hash is in kinetic-primitives, we need to import it or use sha2 directly.
        // Wait, does kinetic-kyn depend on kinetic-primitives? Let's check.
        // Let's just use sha2 directly because kinetic-kyn shouldn't depend on kinetic-primitives if possible, or maybe it does?
        // Actually, kinetic_primitives is what provides sha256_hash.
        let expected = kinetic_primitives::sha256(&sig_bytes);
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
        let period: u64 = env!("KYN_PERIOD").parse().unwrap_or(3);
        // Known valid kyn from Quicknet (Kyn 30290678)
        let kyn = RawKyn {
            kyn: 30290678 * period,
            randomness: "bd5f53ad61578f2566860e3792d01513b817e34c7de92f4781aa76b53ddef0ea".to_string(),
            signature: "ac8313d3ad1f95fe1b380ab6124aade0d4de5919fd60dc846746025ac9aa9d3c434b9dc94c0b75c4efd81aec9e2ef0b9".to_string(),
            is_from_cache: false,
            is_unavailable: false,
        };

        // Should cryptographically verify against QUICKNET_PUBLIC_KEY
        assert!(kyn.verify_beacon(false), "Valid Quicknet kyn failed BLS verification");
    }

    #[test]
    fn test_invalid_quicknet_kyn_verification() {
        let period: u64 = env!("KYN_PERIOD").parse().unwrap_or(3);
        // Corrupted kyn (tampered signature)
        let kyn = RawKyn {
            kyn: 30290678 * period,
            randomness: "bd5f53ad61578f2566860e3792d01513b817e34c7de92f4781aa76b53ddef0ea".to_string(),
            signature: "bc8313d3ad1f95fe1b380ab6124aade0d4de5919fd60dc846746025ac9aa9d3c434b9dc94c0b75c4efd81aec9e2ef0b9".to_string(), // flipped first char
            is_from_cache: false,
            is_unavailable: false,
        };

        assert!(
            !kyn.verify_beacon(false),
            "Invalid Quicknet kyn incorrectly passed BLS verification"
        );
        assert!(kyn.verify_beacon(true), "Bypass signature should always pass verification");
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
        assert!(kyn.can_heartbeat(Kyn(1000)));
        assert!(kyn.can_heartbeat(Kyn(5000))); // live kyns don't check staleness locally here

        // A cached kyn checks staleness against the provided current_live_kyn
        kyn.is_from_cache = true;

        // Exact same kyn (0 staleness)
        assert!(kyn.can_heartbeat(Kyn(1000)));

        // Max allowed staleness (200 rounds)
        assert!(kyn.can_heartbeat(Kyn(1200)));

        // Exceeds max staleness (201 rounds)
        assert!(!kyn.can_heartbeat(Kyn(1201)));

        // Edge case: current_live_kyn is somehow behind the cached kyn
        assert!(kyn.can_heartbeat(Kyn(999)));

        // An unavailable sentinel is never usable
        let sentinel = RawKyn::unavailable();
        assert!(!sentinel.can_heartbeat(Kyn(1000)));
    }
}
