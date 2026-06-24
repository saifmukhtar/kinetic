use serde::{Serialize, Deserialize};

/// Maximum age of a VDF proof in drand rounds (~1 year at 30s/round)
pub const RESQUARING_EPOCH_ROUNDS: u64 = 1_051_200;

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
pub struct CommitRequest {
    pub name: String,
    pub commitment: Commitment,
}

fn default_protocol_version() -> u8 { 1 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reveal {
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u8,
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
        if self.protocol_version >= 2 {
            bytes.push(self.protocol_version);
        }
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
    pub salt: [u8; 32],
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
        bytes.extend_from_slice(&self.salt);
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
    // CALIBRATION NEEDED: Conservative estimates based on ~300k ips.
    let label = name.trim_end_matches('.');
    let len = label.split('.').next().unwrap_or("").chars().count();
    
    let base: u64 = match len {
        0 | 1 => 8_640_000_000,
        2     => 2_160_000_000,
        3     =>   540_000_000,
        4     =>   144_000_000,
        5..=8 =>    36_000_000,
        9..=15 =>   12_000_000,
        _     =>    3_000_000,
    };
    
    // ~1% per 12-hour epoch to account for Moore's Law (1440 rounds = 12 hours at 30s/round)
    let epochs_since_genesis = current_drand_round / 1440;
    let multiplier = 1.0f64 + 0.01 * (epochs_since_genesis as f64);
    (base as f64 * multiplier) as u64
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

    #[test]
    fn test_dynamic_difficulty_lengths() {
        let r0 = 0;
        // 1 char
        assert_eq!(calculate_required_iterations("a", r0), 8_640_000_000);
        // 2 chars
        assert_eq!(calculate_required_iterations("ab", r0), 2_160_000_000);
        // 3 chars
        assert_eq!(calculate_required_iterations("abc", r0), 540_000_000);
        // 4 chars
        assert_eq!(calculate_required_iterations("abcd", r0), 144_000_000);
        // 6 chars
        assert_eq!(calculate_required_iterations("abcdef", r0), 36_000_000);
        // 10 chars
        assert_eq!(calculate_required_iterations("abcdefghij", r0), 12_000_000);
        // 16 chars
        assert_eq!(calculate_required_iterations("abcdefghijklmnop", r0), 3_000_000);
    }

    #[test]
    fn test_difficulty_moores_law_decay() {
        let base = calculate_required_iterations("abcdef", 0); // 36M
        
        // Exactly 1 epoch (1440 rounds)
        let one_epoch = calculate_required_iterations("abcdef", 1440);
        assert_eq!(one_epoch, (base as f64 * 1.01) as u64);

        // 100 epochs
        let hundred_epochs = calculate_required_iterations("abcdef", 144000);
        assert_eq!(hundred_epochs, (base as f64 * 2.0) as u64); // +100%
    }
}
