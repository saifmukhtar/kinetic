//! Custom Kinetic DNS Tree protocol (`kintree`) for discovering bootstrap peer addresses via DNS TXT records.

use libp2p::Multiaddr;
use std::collections::HashSet;

/// Resolves a domain using the Custom Kinetic DNS Tree protocol (kintree).
/// It first checks the domain for a `kintree-root` TXT record. If found, it traverses
/// the branches to discover `kintree-leaf` records containing full Multiaddrs.
/// If no root is found, it falls back to parsing flat Multiaddrs directly from the root domain's TXT records.
#[cfg(not(target_arch = "wasm32"))]
pub async fn resolve_dns_tree(domain: &str) -> Vec<Multiaddr> {
    let mut addrs = Vec::new();
    let resolver = match hickory_resolver::AsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("KIN-NRS-055: Failed to initialize DNS resolver: {}", e);
            return addrs;
        }
    };

    let root_records = match resolver.txt_lookup(domain).await {
        Ok(res) => res,
        Err(e) => {
            tracing::warn!("KIN-NRS-056: DNS lookup failed for {}: {}", domain, e);
            return addrs;
        }
    };

    let mut root_hash = None;

    for record in root_records {
        for raw_txt in record.txt_data() {
            if let Ok(txt_str) = std::str::from_utf8(raw_txt) {
                if txt_str.starts_with("kintree-root:v1") {
                    if let Some(hash_part) = txt_str.split(" e=").nth(1) {
                        let hash = hash_part.split_whitespace().next().unwrap_or(hash_part);
                        root_hash = Some(hash.to_string());
                    }
                } else if (txt_str.starts_with("/ip4/") || txt_str.starts_with("/ip6/"))
                    && let Ok(ma) = txt_str.trim().parse::<Multiaddr>()
                {
                    addrs.push(ma);
                }
            }
        }
    }

    if let Some(hash) = root_hash {
        tracing::info!("Found DNS tree root at {}. Traversing...", domain);
        let mut branches_to_visit = vec![hash];
        let mut visited = HashSet::new();

        let max_lookups = 20;
        let mut lookups = 0;

        while let Some(branch_hash) = branches_to_visit.pop() {
            if lookups >= max_lookups || addrs.len() >= 50 {
                break;
            }
            if !visited.insert(branch_hash.clone()) {
                continue;
            }
            lookups += 1;

            let branch_domain = format!("{}.{}", branch_hash, domain);
            if let Ok(response) = resolver.txt_lookup(branch_domain.as_str()).await {
                for record in response {
                    for raw_txt in record.txt_data() {
                        if let Ok(txt_str) = std::str::from_utf8(raw_txt) {
                            if txt_str.starts_with("kintree-branch:") {
                                let parts = txt_str.trim_start_matches("kintree-branch:");
                                for h in parts.split(',') {
                                    let h = h.trim();
                                    if !h.is_empty() {
                                        branches_to_visit.push(h.to_string());
                                    }
                                }
                            } else if txt_str.starts_with("kintree-leaf:") {
                                let ma_str = txt_str.trim_start_matches("kintree-leaf:").trim();
                                if let Ok(ma) = ma_str.parse::<Multiaddr>() {
                                    addrs.push(ma);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    addrs
}

#[cfg(target_arch = "wasm32")]
/// Resolves a domain using the Custom Kinetic DNS Tree protocol (kintree).
pub async fn resolve_dns_tree(_domain: &str) -> Vec<Multiaddr> {
    Vec::new()
}
