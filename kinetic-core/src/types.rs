use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VdfProof {
    /// The serialized mathematical proof (e.g., from the Chia Class Group VDF)
    pub proof_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reveal {
    /// The human-readable handle being registered
    pub name: String,
    /// The actual data bound to this name (e.g. an IP address)
    pub payload: Vec<u8>,
    /// The cryptographic salt used to prevent dictionary attacks prior to reveal
    pub salt: [u8; 32],
    /// The specific Drand pulse round number bound to this commitment
    pub drand_pulse: u64,
    pub drand_randomness: String,
    pub iterations: u64,
    /// The VDF proof solving the sequential puzzle
    pub vdf_proof: VdfProof,
    /// The public key claiming this name
    pub pubkey: Vec<u8>,
    /// The signature of the reveal tuple to prevent front-running hijacking
    pub signature: Vec<u8>,
}

impl Reveal {
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.drand_pulse.to_be_bytes());
        bytes.extend_from_slice(self.drand_randomness.as_bytes());
        bytes.extend_from_slice(&self.iterations.to_be_bytes());
        bytes.extend_from_slice(&self.vdf_proof.proof_bytes);
        bytes.extend_from_slice(&self.pubkey);
        bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub name: String,
    pub latest_drand_pulse: u64,
    pub signature: Vec<u8>,
}

impl Heartbeat {
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&self.latest_drand_pulse.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hibernation {
    pub name: String,
    pub drand_pulse: u64,
    pub drand_randomness: String,
    pub iterations: u64,
    pub vdf_proof: VdfProof,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Hibernation {
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"HIBERNATION");
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&self.drand_pulse.to_be_bytes());
        bytes.extend_from_slice(self.drand_randomness.as_bytes());
        bytes.extend_from_slice(&self.iterations.to_be_bytes());
        bytes.extend_from_slice(&self.vdf_proof.proof_bytes);
        bytes.extend_from_slice(&self.pubkey);
        bytes
    }
}

pub const M_REDUNDANCY: u8 = 5;

/// Deterministically derive the `M` Kademlia DHT storage keys for a given name.
/// This prevents single-key eclipse attacks.
pub fn derive_storage_keys(name: &str) -> Vec<[u8; 32]> {
    use sha2::{Sha256, Digest};
    let mut keys = Vec::with_capacity(M_REDUNDANCY as usize);
    
    for i in 0..M_REDUNDANCY {
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        hasher.update(&[i]);
        hasher.update(b"kinetic-dht-v1");
        
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        keys.push(key);
    }
    keys
}

/// Calculate the minimum required VDF iterations based on name length to prevent squatting.
pub fn calculate_required_iterations(name: &str, current_drand_round: u64) -> u64 {
    let base_name = name.trim_end_matches(".kin.").trim_end_matches(".kin");
    let len = base_name.len();
    
    let base_diff = match len {
        0..=1 => 10_000_000,
        2 => 5_000_000,
        3 => 1_000_000,
        4 => 500_000,
        _ => 100_000,
    };
    
    // Scale difficulty by exactly 1 iteration per drand round.
    // At 1 pulse per 30s, this adds ~1,051,200 iterations per year to offset Moore's Law.
    base_diff + current_drand_round
}

pub fn load_or_create_keypair() -> std::io::Result<ed25519_dalek::SigningKey> {
    use std::path::PathBuf;
    use directories::ProjectDirs;
    use std::fs;

    let key_path = std::env::var("KINETIC_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            ProjectDirs::from("com", "kinetic", "kinetic")
                .map(|d| d.config_dir().join("id.bin"))
                .unwrap_or_else(|| PathBuf::from("/tmp/kinetic_id.bin"))
        });

    if let Some(parent) = key_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    if key_path.exists() {
        let bytes = fs::read(&key_path)?;
        if bytes.len() == 32 {
            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            return Ok(ed25519_dalek::SigningKey::from_bytes(&array));
        }
    }

    let mut bytes = [0u8; 32];
    if getrandom::fill(&mut bytes).is_err() {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Random generation failed"));
    }
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
    let _ = fs::write(&key_path, signing_key.to_bytes());
    Ok(signing_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_storage_keys() {
        let keys = derive_storage_keys("alice.kin");
        assert_eq!(keys.len(), 5);
        
        // Ensure keys are unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
        
        // Ensure determinism
        let keys2 = derive_storage_keys("alice.kin");
        assert_eq!(keys, keys2);
    }
}
