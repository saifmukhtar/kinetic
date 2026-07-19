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

pub(crate) struct PendingPut {
    pub(crate) responder:
        oneshot::Sender<std::result::Result<(), kinetic_core::error::PublishError>>,
    pub(crate) expected_responses: usize,
    pub(crate) success_count: usize,
}

pub(crate) fn spawn<F>(future: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(future);

    #[cfg(not(target_arch = "wasm32"))]
    tokio::spawn(future);
}

pub(crate) async fn spawn_blocking<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    #[cfg(target_arch = "wasm32")]
    {
        // On WASM, we don't have true blocking threads, so we just run it synchronously.
        f()
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::task::spawn_blocking(f).await.unwrap()
    }
}

pub(crate) fn is_routable_multiaddr(addr: &libp2p::Multiaddr, disable_pow: bool) -> bool {
    if kinetic_core::config::is_dev_mode() || disable_pow {
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
                return true;
            }
            _ => {}
        }
    }
    true
}

impl super::core::NetworkEventLoop {
    /// Resolves conflicts when multiple records are found for the same Kademlia key.
    pub fn xor_tie_breaker(
        query_name: &str,
        payloads: Vec<Vec<u8>>,
        current_pulse: u64,
    ) -> Option<Vec<u8>> {
        if payloads.is_empty() {
            return None;
        }

        let mut pulse_bytes = [0u8; 32];
        pulse_bytes[..8].copy_from_slice(&current_pulse.to_be_bytes());

        // Deduplicate payloads in-place
        let mut unique_payloads = payloads;
        unique_payloads.sort_unstable();
        unique_payloads.dedup();

        // Single-pass parsing
        enum ParsedPayload {
            Kid(kinetic_kid::KidDocument),
            Reveal(kinetic_core::types::Reveal),
            HostRouting(kinetic_core::types::HostRoutingRecord),
        }

        let mut parsed = Vec::new();
        let mut is_kid = false;
        let mut is_host_routing = false;

        for p in unique_payloads {
            if let Ok(doc) = serde_json::from_slice::<kinetic_kid::KidDocument>(&p) {
                if doc.kid.to_string() == query_name {
                    is_kid = true;
                    parsed.push((p, ParsedPayload::Kid(doc)));
                }
            } else if let Ok(host_route) =
                serde_json::from_slice::<kinetic_core::types::HostRoutingRecord>(&p)
            {
                if query_name == format!("routing:{}", host_route.host_id) {
                    is_host_routing = true;
                    parsed.push((p, ParsedPayload::HostRouting(host_route)));
                }
            } else if let Ok(reveal) = serde_json::from_slice::<kinetic_core::types::Reveal>(&p) {
                if reveal.name == query_name && reveal.validate().is_ok() {
                    parsed.push((p, ParsedPayload::Reveal(reveal)));
                }
            }
        }

        if is_kid {
            let current_time = web_time::SystemTime::now()
                .duration_since(web_time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            parsed
                .into_iter()
                .filter_map(|(p, parsed_payload)| {
                    if let ParsedPayload::Kid(doc) = parsed_payload {
                        #[cfg(not(test))]
                        if doc.verify().is_err() {
                            return None;
                        }

                        // Reject future-dated documents (allowing 300s clock drift)
                        if doc.created_at > current_time + 300 {
                            tracing::warn!(
                                "Rejecting KidDocument: created_at ({}) is in the future",
                                doc.created_at
                            );
                            return None;
                        }

                        Some((p, u64::MAX - doc.created_at)) // Sort by newest created_at
                    } else {
                        None
                    }
                })
                .min_by_key(|(_, dist)| *dist)
                .map(|(p, _)| p)
        } else if is_host_routing {
            parsed
                .into_iter()
                .filter_map(|(p, parsed_payload)| {
                    if let ParsedPayload::HostRouting(record) = parsed_payload {
                        if crate::store::verification::verify_host_routing_record(&record).is_err()
                        {
                            return None;
                        }
                        Some((p, u64::MAX - record.timestamp)) // Sort by newest timestamp
                    } else {
                        None
                    }
                })
                .min_by_key(|(_, dist)| *dist)
                .map(|(p, _)| p)
        } else {
            // It's a Reveal query. Sort by XOR distance first, then lazily verify VDFs.
            let mut candidates = parsed
                .into_iter()
                .filter_map(|(p, parsed_payload)| {
                    if let ParsedPayload::Reveal(reveal) = parsed_payload {
                        let y_bytes: [u8; 32] = reveal
                            .vdf_proof
                            .proof_bytes
                            .get(..32)
                            .and_then(|b| b.try_into().ok())
                            .unwrap_or([0u8; 32]);

                        let mut dist = [0u8; 32];
                        for (i, (y, p)) in std::iter::zip(y_bytes, pulse_bytes).enumerate() {
                            dist[i] = y ^ p;
                        }
                        Some((p, reveal, dist))
                    } else {
                        None
                    }
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
                        tracing::warn!(
                            error_code = "KIN-RES-004",
                            name = %reveal.name,
                            "Skipping candidate: Invalid signature in tie-breaker"
                        );
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

                    if current_pulse.saturating_sub(reveal.drand_pulse)
                        > kinetic_core::types::RESQUARING_EPOCH_ROUNDS
                    {
                        tracing::warn!(
                            error_code = "KIN-RES-005",
                            name = %reveal.name,
                            "Skipping candidate: Reveal expired (older than RESQUARING_EPOCH_ROUNDS)"
                        );
                        continue;
                    }

                    let engine = ChiaVdfEngine::new();

                    let required_iterations =
                        match crate::store::verification::compute_required_iterations(
                            &reveal,
                            current_pulse,
                            &engine,
                        ) {
                            Ok(req) => req,
                            Err(e) => {
                                tracing::warn!(
                                    error_code = "KIN-RES-006",
                                    name = %reveal.name,
                                    "Skipping candidate: failed to compute required iterations: {:?}", e
                                );
                                continue;
                            }
                        };

                    if reveal.iterations < required_iterations {
                        tracing::warn!(
                            error_code = "KIN-RES-007",
                            name = %reveal.name,
                            "Skipping candidate: Insufficient VDF iterations. Provided {}, Required {}",
                            reveal.iterations, required_iterations
                        );
                        continue;
                    }

                    let challenge_cmt = kinetic_core::types::Commitment { hash };
                    match engine.verify(&challenge_cmt, &reveal.vdf_proof, reveal.iterations) {
                        Ok(true) => return Some(p),
                        Ok(false) => {
                            tracing::warn!(
                                error_code = "KIN-RES-008",
                                name = %reveal.name,
                                "Skipping candidate: VDF verification failed"
                            );
                            continue;
                        }
                        Err(kinetic_core::error::VdfError::UnsupportedPlatform) => {
                            tracing::error!(
                                error_code = "KIN-RES-009",
                                name = %reveal.name,
                                "VDF verification is unsupported on this platform. Resolution failed."
                            );
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!(
                                error_code = "KIN-RES-010",
                                name = %reveal.name,
                                "Skipping candidate: VDF verification error: {:?}", e
                            );
                            continue;
                        }
                    }
                }
                #[cfg(test)]
                {
                    return Some(p);
                }
            }
            None
        }
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
            protocol_version: 2,
            name: "dummy.kin".to_string(),
            payload: vec![],
            salt: [0u8; 32],
            drand_pulse: 0,
            drand_randomness: "".to_string(),
            vdf_proof: VdfProof { proof_bytes },
            iterations: 1000,
            pubkey: vec![],
            signature: vec![],
            miner_pubkey: None,
            previous_proof: None,
        };
        serde_json::to_vec(&reveal).unwrap()
    }

    #[test]
    fn test_xor_tie_breaker() {
        let payload_a = make_dummy_reveal(0x10);
        let payload_b = make_dummy_reveal(0x05);

        let winner = NetworkEventLoop::xor_tie_breaker(
            "dummy.kin",
            vec![payload_a.clone(), payload_b.clone()],
            0,
        );
        assert_eq!(winner.unwrap(), payload_b);

        let pulse: u64 = 0x1500_0000_0000_0000;
        let winner2 = NetworkEventLoop::xor_tie_breaker(
            "dummy.kin",
            vec![payload_a.clone(), payload_b.clone()],
            pulse,
        );
        assert_eq!(winner2.unwrap(), payload_a);
    }
}
