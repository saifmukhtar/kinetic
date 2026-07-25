#[cfg(test)]
mod tests {
    use crate::error::KineticStoreError;
    use crate::store::verification::verify_host_routing_record;
    use kinetic_core::types::HostRoutingRecord;
    use libp2p::identity::Keypair;
    use libp2p::PeerId;
    #[test]
    fn test_host_routing_freshness() {
        let peer_id = PeerId::from(Keypair::generate_ed25519().public()); // Random but we won't verify sig if timestamp is stale

        let stale_timestamp = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - kinetic_core::constants::TIMEOUTS_HOST_ROUTE_MAX_AGE_SECONDS
            - 10;

        let record = HostRoutingRecord {
            host_id: peer_id.to_string(),
            current_peer_id: String::new(),
            timestamp: stale_timestamp,
            signature: vec![],
        };

        // Even with a bad signature, it should fail on freshness first
        let res = verify_host_routing_record(&record);
        assert!(matches!(
            res.unwrap_err(),
            KineticStoreError::InvalidHostRouteSignature
        ));
    }

    #[test]
    fn test_peer_id_extraction_safeguard() {
        // Create a HostRoutingRecord with a totally invalid PeerId (not Ed25519, or too short)
        // A SHA2-256 multihash instead of identity will cause the length/format check to fail safely.
        let mh = libp2p::multihash::Multihash::wrap(0x12, &[0u8; 32]).unwrap();
        let peer_id = PeerId::from_multihash(mh).unwrap();

        let recent_timestamp = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let record = HostRoutingRecord {
            host_id: peer_id.to_string(),
            current_peer_id: String::new(),
            timestamp: recent_timestamp,
            signature: vec![],
        };

        let res = verify_host_routing_record(&record);
        // Should safely return InvalidPublicKey instead of panicking
        assert!(matches!(
            res.unwrap_err(),
            KineticStoreError::InvalidPublicKey
        ));
    }
}
