//! Local cache for storing dialable public peers to avoid central bootstrap reliance.

use libp2p::{Multiaddr, PeerId};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;

/// A limited-size registry of known peers with public IP addresses.
pub struct PeerRegistry {
    /// The underlying LRU cache storing peer addresses.
    pub cache: LruCache<PeerId, Vec<Multiaddr>>,
}

#[derive(Serialize, Deserialize)]
struct RegistryData {
    peers: Vec<(Vec<u8>, Vec<Vec<u8>>)>,
}

impl PeerRegistry {
    /// Create a new PeerRegistry with a specified capacity limit.
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: LruCache::new(
                NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(500).unwrap()),
            ),
        }
    }

    /// Loads the registry from the provided JSON bytes
    pub fn from_bytes(capacity: usize, data: &[u8]) -> Result<Self, kinetic_core::error::P2pError> {
        let mut registry = Self::new(capacity);
        let parsed = serde_json::from_slice::<RegistryData>(data)
            .map_err(|e| kinetic_core::error::P2pError::PeerRegistryCorruption(e.to_string()))?;

        for (peer_bytes, addrs_bytes) in parsed.peers {
            if let Ok(peer) = PeerId::from_bytes(&peer_bytes) {
                let addrs: Vec<Multiaddr> = addrs_bytes
                    .into_iter()
                    .filter_map(|b| Multiaddr::try_from(b).ok())
                    .collect();
                if !addrs.is_empty() {
                    registry.cache.put(peer, addrs);
                }
            } else {
                return Err(kinetic_core::error::P2pError::PeerRegistryCorruption(
                    "Invalid PeerId bytes".into(),
                ));
            }
        }
        Ok(registry)
    }

    /// Serializes the registry to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, kinetic_core::error::P2pError> {
        let peers: Vec<(Vec<u8>, Vec<Vec<u8>>)> = self
            .cache
            .iter()
            .map(|(peer, addrs)| {
                let addrs_bytes = addrs.iter().map(|a| a.to_vec()).collect();
                (peer.to_bytes(), addrs_bytes)
            })
            .collect();
        let data = RegistryData { peers };
        serde_json::to_vec(&data)
            .map_err(|e| kinetic_core::error::P2pError::PeerRegistrySerialization(e.to_string()))
    }

    /// Checks if a Multiaddr contains a public IPv4/IPv6 address.
    /// Safely defaults to false and rigorously blocks private/special ranges.
    fn is_public_addr(addr: &Multiaddr) -> bool {
        let mut has_public = false;
        for proto in addr.iter() {
            match proto {
                libp2p::core::multiaddr::Protocol::Ip4(ip) => {
                    let octets = ip.octets();
                    // Block loopback, unspecified, broadcast
                    if ip.is_loopback() || ip.is_unspecified() || ip.is_broadcast() {
                        return false;
                    }
                    // Private ranges (10.x, 172.16-31.x, 192.168.x)
                    if octets[0] == 10
                        || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                        || (octets[0] == 192 && octets[1] == 168)
                    {
                        return false;
                    }
                    // Link-local (169.254.x.x)
                    if octets[0] == 169 && octets[1] == 254 {
                        return false;
                    }
                    // Carrier-grade NAT (100.64.0.0/10)
                    if octets[0] == 100 && (octets[1] & 0b1100_0000 == 0b0100_0000) {
                        return false;
                    }
                    // Multicast and Experimental (224.0.0.0/4 and above)
                    if octets[0] >= 224 {
                        return false;
                    }
                    has_public = true;
                }
                libp2p::core::multiaddr::Protocol::Ip6(ip) => {
                    if ip.is_loopback() || ip.is_unspecified() {
                        return false;
                    }
                    let segments = ip.segments();
                    // ULA (fc00::/7)
                    if segments[0] & 0xfe00 == 0xfc00 {
                        return false;
                    }
                    // Link-local (fe80::/10)
                    if segments[0] & 0xffc0 == 0xfe80 {
                        return false;
                    }
                    // Multicast (ff00::/8)
                    if segments[0] & 0xff00 == 0xff00 {
                        return false;
                    }
                    has_public = true;
                }
                _ => {}
            }
        }
        has_public
    }

    /// Bumps a peer's LRU cache position to mark them as recently used/connected.
    pub fn mark_connected(&mut self, peer: &PeerId) {
        let _ = self.cache.get(peer);
    }

    /// Adds a peer if they have at least one public IP.
    pub fn add_verified_peer(&mut self, peer: PeerId, addrs: Vec<Multiaddr>) -> bool {
        let public_addrs: Vec<Multiaddr> = addrs
            .into_iter()
            .filter(|a| Self::is_public_addr(a))
            .collect();

        if !public_addrs.is_empty() {
            self.cache.put(peer, public_addrs);
            true
        } else {
            false
        }
    }
}
