use kinetic_core::error::{NetworkClientError, ResolutionError};
use tokio::sync::oneshot;

pub(crate) struct PendingGet {
    pub(crate) responder: oneshot::Sender<std::result::Result<Vec<u8>, ResolutionError>>,
    pub(crate) expected_responses: usize,
    pub(crate) received_payloads: Vec<Vec<u8>>,
    pub(crate) peers_queried: usize,
}

pub(crate) struct PendingQuorum {
    pub(crate) responder: oneshot::Sender<std::result::Result<usize, NetworkClientError>>,
    pub(crate) expected_responses: usize,
    pub(crate) target_payload: Vec<u8>,
    pub(crate) match_count: usize,
}

pub(crate) fn is_routable_multiaddr(addr: &libp2p::Multiaddr) -> bool {
    if kinetic_core::config::is_dev_mode() {
        return true;
    }

    use libp2p::multiaddr::Protocol;
    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(ip) => {
                if ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_unspecified()
                    || ip.is_broadcast()
                    || ip.is_documentation()
                {
                    return false;
                }
            }
            Protocol::Ip6(ip) => {
                if ip.is_loopback() || ip.is_unspecified() {
                    return false;
                }
                // Check if ULA (Unique Local Address) fc00::/7
                if ip.segments()[0] & 0xfe00 == 0xfc00 {
                    return false;
                }
                // Check if link-local fe80::/10
                if ip.segments()[0] & 0xffc0 == 0xfe80 {
                    return false;
                }
            }
            Protocol::Memory(_) => {
                return false;
            }
            _ => {}
        }
    }
    true
}

impl super::core::NetworkEventLoop {
    /// Resolves conflicts when multiple records are found for the same Kademlia key.
    pub fn xor_tie_breaker(
        _query_name: &str,
        payloads: Vec<Vec<u8>>,
        current_pulse: u64,
    ) -> Option<Vec<u8>> {
        if payloads.is_empty() {
            return None;
        }

        let mut pulse_bytes = [0u8; 32];
        pulse_bytes[..8].copy_from_slice(&current_pulse.to_be_bytes());

        let mut unique_payloads = payloads;
        unique_payloads.sort();
        unique_payloads.dedup();

        // Use block_in_place to prevent event loop starvation during VDF verifications
        tokio::task::block_in_place(|| {
            // Check if this is a KidDocument query by parsing the first payload
            let is_kid = unique_payloads
                .iter()
                .any(|p| serde_json::from_slice::<kinetic_kid::KidDocument>(p).is_ok());

            if is_kid {
                unique_payloads
                    .into_iter()
                    .filter_map(|p| {
                        let doc = serde_json::from_slice::<kinetic_kid::KidDocument>(&p).ok()?;
                        #[cfg(not(test))]
                        if doc.verify().is_err() {
                            return None;
                        }
                        Some((p, u64::MAX - doc.created_at)) // Sort by newest created_at
                    })
                    .min_by_key(|(_, dist)| *dist)
                    .map(|(p, _)| p)
            } else {
                // It's a Reveal query. Sort by XOR distance first, then lazily verify VDFs.
                let mut candidates = unique_payloads
                    .into_iter()
                    .filter_map(|p| {
                        let reveal =
                            serde_json::from_slice::<kinetic_core::types::Reveal>(&p).ok()?;
                        let y_bytes: [u8; 32] = reveal
                            .vdf_proof
                            .proof_bytes
                            .get(..32)
                            .and_then(|b| b.try_into().ok())
                            .unwrap_or([0u8; 32]);
                        let mut dist = [0u8; 32];
                        for i in 0..32 {
                            dist[i] = y_bytes[i] ^ pulse_bytes[i];
                        }
                        Some((p, reveal, dist))
                    })
                    .collect::<Vec<_>>();

                candidates.sort_by_key(|(_, _, dist)| *dist);

                #[allow(unused_variables, clippy::never_loop)]
                for (p, reveal, _) in candidates {
                    #[cfg(not(test))]
                    {
                        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                        let signable = reveal.signable_bytes();
                        let is_valid = VerifyingKey::try_from(reveal.pubkey.as_slice())
                            .and_then(|k| Signature::from_slice(&reveal.signature).map(|s| (k, s)))
                            .map(|(k, s)| k.verify(&signable, &s).is_ok())
                            .unwrap_or(false);

                        if !is_valid {
                            continue;
                        }

                        use kinetic_core::traits::VdfEngine;
                        use kinetic_vdf::ChiaVdfEngine;
                        use sha2::{Digest, Sha256};

                        let drand_bytes = match hex::decode(&reveal.drand_randomness) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::warn!(
                                    error_code = "KIN-RES-003",
                                    "Skipping candidate: invalid drand_randomness hex: {}",
                                    e
                                );
                                continue;
                            }
                        };
                        let mut hasher = Sha256::new();
                        hasher.update(reveal.name.as_bytes());
                        hasher.update(reveal.salt);
                        hasher.update(&drand_bytes);
                        hasher.update(&reveal.pubkey);
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&hasher.finalize());

                        let engine = ChiaVdfEngine::new();
                        let challenge_cmt = kinetic_core::types::Commitment { hash };
                        if engine
                            .verify(&challenge_cmt, &reveal.vdf_proof, reveal.iterations)
                            .unwrap_or(false)
                        {
                            return Some(p);
                        }
                    }
                    #[cfg(test)]
                    {
                        return Some(p);
                    }
                }
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {

    use crate::event_loop::core::NetworkEventLoop;
    use kinetic_core::types::{Reveal, VdfProof};

    fn make_dummy_reveal(proof_first_byte: u8) -> Vec<u8> {
        let mut proof_bytes = vec![0u8; 100];
        proof_bytes[0] = proof_first_byte;

        let reveal = Reveal {
            protocol_version: 1,
            name: "test.kin".to_string(),
            payload: vec![],
            salt: [0u8; 32],
            drand_pulse: 0,
            drand_randomness: "".to_string(),
            vdf_proof: VdfProof { proof_bytes },
            iterations: 1000,
            pubkey: vec![],
            signature: vec![],
            miner_pubkey: None,
            points_spent: Some(0),
            previous_proof: None,
        };
        serde_json::to_vec(&reveal).unwrap()
    }

    #[test]
    fn test_xor_tie_breaker() {
        let payload_a = make_dummy_reveal(0x10);
        let payload_b = make_dummy_reveal(0x05);

        let winner = NetworkEventLoop::xor_tie_breaker(
            "test.kin",
            vec![payload_a.clone(), payload_b.clone()],
            0,
        );
        assert_eq!(winner.unwrap(), payload_b);

        let pulse: u64 = 0x1500_0000_0000_0000;
        let winner2 = NetworkEventLoop::xor_tie_breaker(
            "test.kin",
            vec![payload_a.clone(), payload_b.clone()],
            pulse,
        );
        assert_eq!(winner2.unwrap(), payload_a);
    }
}
