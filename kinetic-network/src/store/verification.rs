use crate::error::KineticStoreError;

/// Finding 13 (Critical): Verify a HostRoutingRecord's signature and timestamp freshness.
/// This lives in kinetic-network (not kinetic-core) because it requires the libp2p dependency
/// to extract the Ed25519 public key from the PeerId multihash.
pub(crate) fn verify_host_routing_record(
    record: &kinetic_core::types::HostRoutingRecord,
) -> Result<(), KineticStoreError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Enforce timestamp freshness — reject records older than 10 minutes.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| KineticStoreError::InvalidHostRouteSignature)?
        .as_secs();
    if now.saturating_sub(record.timestamp) > 600 {
        tracing::warn!(
            "HostRoutingRecord for {} is stale ({} seconds old)",
            record.host_id,
            now.saturating_sub(record.timestamp)
        );
        return Err(KineticStoreError::InvalidHostRouteSignature);
    }

    // Parse the host_id as a libp2p PeerId and extract its public key.
    let host_peer_id = record
        .host_id
        .parse::<libp2p::PeerId>()
        .map_err(|_| KineticStoreError::InvalidPublicKey)?;

    // Extract the Ed25519 public key bytes from the PeerId multihash.
    // libp2p Ed25519 PeerIds encode the 32-byte public key in their multihash payload.
    let pubkey_bytes: [u8; 32] = match host_peer_id.as_ref().digest() {
        bytes if bytes.len() >= 36 => {
            // Multihash format: <varint code> <varint length> <payload>
            // For identity multihash, the payload starts at byte 2 and contains
            // the protobuf-encoded public key. The last 32 bytes are the raw ed25519 key.
            let payload = &bytes[bytes.len() - 32..];
            let mut arr = [0u8; 32];
            arr.copy_from_slice(payload);
            arr
        }
        _ => return Err(KineticStoreError::InvalidPublicKey),
    };

    let verifying_key =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| KineticStoreError::InvalidPublicKey)?;

    let sig = Signature::from_slice(&record.signature)
        .map_err(|_| KineticStoreError::MalformedSignature)?;

    let signable = record.signable_bytes();
    verifying_key
        .verify(&signable, &sig)
        .map_err(|_| KineticStoreError::InvalidHostRouteSignature)
}
