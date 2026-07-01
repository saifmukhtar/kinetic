use libp2p::{identity::Keypair, PeerId};
use sha2::{Digest, Sha256};
use tracing::info;

pub const EPOCH_PULSES: u64 = 1440; // 12 hours at 30s per pulse
pub const DEFAULT_DIFFICULTY_BITS: u32 = 16;

/// Computes the leading zero bits of a given byte slice.
fn leading_zeros(hash: &[u8]) -> u32 {
    let mut zeros = 0;
    for &byte in hash {
        if byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros();
            break;
        }
    }
    zeros
}

/// Computes a peer-specific epoch to stagger identity churn across the network.
fn get_staggered_epoch(peer_id: &PeerId, pulse: u64) -> u64 {
    let bytes = peer_id.to_bytes();
    let mut offset_bytes = [0u8; 8];
    let len = bytes.len();
    if len >= 8 {
        offset_bytes.copy_from_slice(&bytes[len - 8..len]);
    } else {
        offset_bytes[..len].copy_from_slice(&bytes[..len]);
    }
    let offset = u64::from_be_bytes(offset_bytes) % EPOCH_PULSES;
    (pulse + offset) / EPOCH_PULSES
}

/// Validates if a PeerId has sufficient proof-of-work for the current or previous epoch.
pub fn is_valid_sybil_pow(peer_id: &PeerId, current_pulse: u64, difficulty: u32) -> bool {
    if kinetic_core::config::is_dev_mode() {
        return true;
    }

    let peer_bytes = peer_id.to_bytes();
    let current_epoch = get_staggered_epoch(peer_id, current_pulse);

    // Check current epoch
    let mut hasher = Sha256::new();
    hasher.update(&peer_bytes);
    hasher.update(current_epoch.to_be_bytes());
    if leading_zeros(&hasher.finalize()) >= difficulty {
        return true;
    }

    // Check previous epoch (allows 12-hour overlap so nodes don't drop exactly at the boundary)
    if current_epoch > 0 {
        let mut hasher = Sha256::new();
        hasher.update(&peer_bytes);
        hasher.update((current_epoch - 1).to_be_bytes());
        if leading_zeros(&hasher.finalize()) >= difficulty {
            return true;
        }
    }

    false
}

/// Grinds an Ed25519 keypair whose PeerId satisfies the PoW for the current epoch.
pub fn mine_sybil_keypair(current_pulse: u64, difficulty: u32) -> Keypair {
    let mut attempts: u64 = 0;

    info!(
        "Mining epoch-bound S/Kademlia identity (difficulty: {} bits)...",
        difficulty
    );
    let start = std::time::Instant::now();

    loop {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let peer_bytes = peer_id.to_bytes();
        let current_epoch = get_staggered_epoch(&peer_id, current_pulse);

        let mut hasher = Sha256::new();
        hasher.update(&peer_bytes);
        hasher.update(current_epoch.to_be_bytes());

        attempts += 1;
        if leading_zeros(&hasher.finalize()) >= difficulty {
            info!(
                "Mined S/Kademlia identity {} in {} attempts ({:?})",
                peer_id,
                attempts,
                start.elapsed()
            );
            return keypair;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_mining_and_validation() {
        let pulse = 10_000_000;
        let difficulty = 8; // Low difficulty for fast test
        let kp = mine_sybil_keypair(pulse, difficulty);
        let peer_id = PeerId::from(kp.public());

        // Should be valid for current pulse
        assert!(is_valid_sybil_pow(&peer_id, pulse, difficulty));

        // Should be valid for pulse at the very end of the current epoch
        let end_of_epoch_pulse = (pulse / EPOCH_PULSES) * EPOCH_PULSES + EPOCH_PULSES - 1;
        assert!(is_valid_sybil_pow(&peer_id, end_of_epoch_pulse, difficulty));

        // Should be valid for the NEXT epoch's pulse (because we are the "previous epoch" from its perspective)
        let next_epoch_pulse = pulse + EPOCH_PULSES;
        assert!(is_valid_sybil_pow(&peer_id, next_epoch_pulse, difficulty));

        // Should NOT be valid for pulse 2 epochs away
        let two_epochs_away = pulse + (2 * EPOCH_PULSES);
        assert!(!is_valid_sybil_pow(&peer_id, two_epochs_away, difficulty));

        // Should NOT be valid for pulse 1 epoch ago
        if pulse > EPOCH_PULSES {
            let prev_epoch_pulse = pulse - EPOCH_PULSES;
            assert!(!is_valid_sybil_pow(&peer_id, prev_epoch_pulse, difficulty));
        }
    }
}
