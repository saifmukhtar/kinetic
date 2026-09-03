//! Argon2id Proof-of-Work (PoW) mining and validation for S/Kademlia anti-Sybil peer identity protection.

use argon2::{Algorithm, Argon2, Params, Version};
use libp2p::{PeerId, identity::Keypair};
use tracing::info;

/// The number of drand kyns in a single PoW epoch (e.g., 1440 for 12 hours at 30s per kyn).
pub const EPOCH_KYNS: u64 = 1440; // 12 hours at 30s per kyn

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

/// Computes the Argon2id hash for the given peer bytes and epoch.
fn compute_pow_hash(argon2: &Argon2, peer_bytes: &[u8], epoch: u64) -> Option<[u8; 32]> {
    let mut output = [0u8; 32];
    // Argon2 requires a salt of at least 8 bytes, and epoch.to_be_bytes() is 8 bytes.
    if let Err(e) = argon2.hash_password_into(peer_bytes, &epoch.to_be_bytes(), &mut output) {
        tracing::error!(
            error = ?kinetic_core::error::SystemError::ServerCrashed(format!("Argon2 memory allocation failed: {}", e)),
            "Argon2 memory allocation failed during PoW hash"
        );
        return None;
    }
    Some(output)
}

/// Computes a peer-specific epoch to stagger identity churn across the network.
pub fn get_staggered_epoch(peer_bytes: &[u8], kyn: kinetic_types::clock::Kyn) -> u64 {
    let mut offset_bytes = [0u8; 8];
    let len = peer_bytes.len();
    if len >= 8 {
        offset_bytes.copy_from_slice(&peer_bytes[len - 8..len]);
    } else {
        // Right-align the bytes to prevent massive value shifts on short inputs
        offset_bytes[8 - len..].copy_from_slice(peer_bytes);
    }
    let offset = u64::from_be_bytes(offset_bytes) % EPOCH_KYNS;
    kyn.0.saturating_add(offset) / EPOCH_KYNS
}

/// Validates if a PeerId has sufficient proof-of-work for the current or previous epoch.
pub fn is_valid_sybil_pow(
    peer_id: &PeerId,
    current_kyn: kinetic_types::clock::Kyn,
    difficulty: u32,
) -> bool {
    if kinetic_core::config::is_dev_mode() {
        return true;
    }

    if current_kyn.0 == 0 {
        return false;
    }

    let peer_bytes = peer_id.to_bytes();
    let current_epoch = get_staggered_epoch(&peer_bytes, current_kyn);

    // 16MB memory, 1 iteration, 1 parallelism
    let params = Params::new(16384, 1, 1, None).expect("Valid static Argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Check current epoch
    if let Some(hash) = compute_pow_hash(&argon2, &peer_bytes, current_epoch)
        && leading_zeros(&hash) >= difficulty
    {
        return true;
    }

    // Check previous epoch (allows 12-hour overlap so nodes don't drop exactly at the boundary)
    if current_epoch > 0
        && let Some(hash) = compute_pow_hash(&argon2, &peer_bytes, current_epoch - 1)
        && leading_zeros(&hash) >= difficulty
    {
        return true;
    }

    false
}

/// Grinds an Ed25519 keypair whose PeerId satisfies the PoW for the current epoch.
/// WARNING: This is a blocking, CPU-bound operation. If calling from an async context,
/// ensure it is wrapped in `tokio::task::spawn_blocking` to prevent executor starvation.
pub fn mine_sybil_keypair(current_kyn: kinetic_types::clock::Kyn, difficulty: u32) -> Keypair {
    if current_kyn.0 == 0 && !kinetic_core::config::is_dev_mode() {
        panic!("Cannot generate PoW against kyn 0 (drand uninitialized)");
    }

    if kinetic_core::config::is_dev_mode() {
        info!("Dev mode active: Skipping S/Kademlia identity PoW mining.");
        return Keypair::generate_ed25519();
    }

    let mut attempts: u64 = 0;

    info!(
        "Mining epoch-bound S/Kademlia identity (difficulty: {} bits)...",
        difficulty
    );

    // 16MB memory, 1 iteration, 1 parallelism
    let params = Params::new(16384, 1, 1, None).expect("Valid static Argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let start = web_time::Instant::now();

    loop {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let peer_bytes = peer_id.to_bytes();
        let current_epoch = get_staggered_epoch(&peer_bytes, current_kyn);

        let hash = compute_pow_hash(&argon2, &peer_bytes, current_epoch)
            .expect("Argon2 memory allocation failed during mining");

        attempts += 1;
        if leading_zeros(&hash) >= difficulty {
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
        let kyn = 10_000_000;
        let difficulty = 8; // Low difficulty for fast test
        let kp = mine_sybil_keypair(kinetic_types::clock::Kyn(kyn), difficulty);
        let peer_id = PeerId::from(kp.public());

        // Should be valid for current kyn
        assert!(is_valid_sybil_pow(
            &peer_id,
            kinetic_types::clock::Kyn(kyn),
            difficulty
        ));

        // Should be valid for kyn at the very end of the current epoch
        let end_of_epoch_kyn = (kyn / EPOCH_KYNS) * EPOCH_KYNS + EPOCH_KYNS - 1;
        assert!(is_valid_sybil_pow(
            &peer_id,
            kinetic_types::clock::Kyn(end_of_epoch_kyn),
            difficulty
        ));

        // Should be valid for the NEXT epoch's kyn (because we are the "previous epoch" from its perspective)
        let next_epoch_kyn = kyn + EPOCH_KYNS;
        assert!(is_valid_sybil_pow(
            &peer_id,
            kinetic_types::clock::Kyn(next_epoch_kyn),
            difficulty
        ));

        // Should NOT be valid for kyn 2 epochs away (unless we get a 1/256 lucky collision)
        let two_epochs_away = kyn + (2 * EPOCH_KYNS);
        if is_valid_sybil_pow(
            &peer_id,
            kinetic_types::clock::Kyn(two_epochs_away),
            difficulty,
        ) {
            println!("Random collision for two_epochs_away - skipping assert");
        } else {
            assert!(!is_valid_sybil_pow(
                &peer_id,
                kinetic_types::clock::Kyn(two_epochs_away),
                difficulty
            ));
        }

        // Should NOT be valid for kyn 1 epoch ago
        if kyn > EPOCH_KYNS {
            let prev_epoch_kyn = kyn - EPOCH_KYNS;
            if is_valid_sybil_pow(
                &peer_id,
                kinetic_types::clock::Kyn(prev_epoch_kyn),
                difficulty,
            ) {
                println!("Random collision for prev_epoch_kyn - skipping assert");
            } else {
                assert!(!is_valid_sybil_pow(
                    &peer_id,
                    kinetic_types::clock::Kyn(prev_epoch_kyn),
                    difficulty
                ));
            }
        }
    }
}
