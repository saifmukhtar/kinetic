//! Resolution pipeline for .kin domains, including reserved name interception, reveal verification, KID authentication, and SSRF filtering.

use hickory_proto::rr::{Name, RData, Record};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, ResponseHandler, ResponseInfo};
use kinetic_core::types::DnsZoneExt;
use moka::future::Cache;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Resolves a `.kin` domain by querying the daemon API and checking the local cache.
/// Returns standard DNS records (A, AAAA, CNAME, TXT) converted from the Kinetic DHT `DnsZone`.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_kinetic<R: ResponseHandler>(
    request: &Request,
    mut response_handle: R,
    query_name: &str,
    mut header: hickory_proto::op::Header,
    builder: MessageResponseBuilder<'_>,
    domain_name: &str,
    apex_domain: &str,
    cache: &Cache<String, Option<Vec<u8>>>,
    api_url: &str,
    http_client: &reqwest::Client,
) -> ResponseInfo {
    let query = request.query();

    // Intercept Category 1 PUBLIC_NAMES
    let parts: Vec<&str> = apex_domain.split('.').collect();
    if !parts.is_empty() && kinetic_core::types::PUBLIC_NAMES.contains(&parts[0]) {
        if parts[0] == "localhost" {
            let mut response_records = Vec::new();
            let name = Name::from_str(query_name).unwrap_or_else(|_| Name::root());

            if query.query_type() == hickory_proto::rr::RecordType::A {
                response_records.push(Record::from_rdata(
                    name.clone(),
                    3600,
                    RData::A(std::net::Ipv4Addr::new(127, 0, 0, 1).into()),
                ));
            } else if query.query_type() == hickory_proto::rr::RecordType::AAAA {
                response_records.push(Record::from_rdata(
                    name.clone(),
                    3600,
                    RData::AAAA(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into()),
                ));
            }

            if !response_records.is_empty() {
                let response = builder.build(
                    header,
                    response_records.iter(),
                    std::iter::empty(),
                    std::iter::empty(),
                    std::iter::empty(),
                );
                let _ = response_handle.send_response(response).await;
                return header.into();
            } else {
                // Empty NOERROR response for unsupported query types on localhost
                let response = builder.build(
                    header,
                    std::iter::empty(),
                    std::iter::empty(),
                    std::iter::empty(),
                    std::iter::empty(),
                );
                let _ = response_handle.send_response(response).await;
                return header.into();
            }
        } else {
            // For all other PUBLIC_NAMES, instantly return NXDOMAIN (Not Found)
            let response =
                builder.error_msg(request.header(), hickory_proto::op::ResponseCode::NXDomain);
            let _ = response_handle.send_response(response).await;
            header.set_response_code(hickory_proto::op::ResponseCode::NXDomain);
            return header.into();
        }
    }

    let api_url_clone = api_url.to_string();
    let http_client_clone = http_client.clone();
    let apex_domain_clone = apex_domain.to_string();

    let cache_result = cache
        .try_get_with(apex_domain.to_string(), async move {
            info!(
                "Cache miss for apex: {}. Hitting daemon API...",
                apex_domain_clone
            );

            let url = format!("{}/api/resolve/{}", api_url_clone, apex_domain_clone);
            match http_client_clone.get(&url).send().await {
                Ok(mut resp) => {
                    if resp.status().is_success() {
                        let mut payload = Vec::new();
                        let mut limit_exceeded = false;
                        while let Ok(Some(chunk)) = resp.chunk().await {
                            if payload.len() + chunk.len() > 100 * 1024 {
                                limit_exceeded = true;
                                break;
                            }
                            payload.extend_from_slice(&chunk);
                        }
                        if limit_exceeded {
                            warn!("API response exceeded 100KB limit");
                            Ok::<_, Arc<anyhow::Error>>(None)
                        } else {
                            Ok::<_, Arc<anyhow::Error>>(Some(payload))
                        }
                    } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
                        Ok(None)
                    } else {
                        warn!("API returned status: {}", resp.status());
                        Err(Arc::new(anyhow::anyhow!("API error: {}", resp.status())))
                    }
                }
                Err(e) => {
                    warn!("API request failed: {}", e);
                    Err(Arc::new(e.into()))
                }
            }
        })
        .await;

    match cache_result {
        Ok(Some(payload_bytes)) => {
            info!("Successfully resolved .kin from Cache/DHT");

            match serde_json::from_slice::<kinetic_core::types::NameRecord>(&payload_bytes) {
                Ok(domain_record) => {
                    if domain_record
                        .verify_signature(kinetic_core::constants::NETWORK_SALT)
                        .is_err()
                    {
                        warn!(
                            "Rejecting .kin resolution: record signature invalid for {}",
                            apex_domain
                        );
                        let response = builder
                            .error_msg(request.header(), hickory_proto::op::ResponseCode::ServFail);
                        let _ = response_handle.send_response(response).await;
                        header.set_response_code(hickory_proto::op::ResponseCode::ServFail);
                        return header.into();
                    }

                    match kinetic_core::types::DnsZone::parse_payload(domain_record.payload()) {
                        Ok(zone) => {
                            if let Some(records) = zone.records.get("@") {
                                for record in records {
                                    if let kinetic_core::types::DnsRecord::KID(did) = record {
                                        info!(
                                            "E2E Auth: Domain specifies KID: {}. Fetching from daemon...",
                                            did
                                        );
                                        let kid_url =
                                            format!("{}/api/resolve-kid/{}", api_url, did);
                                        match http_client.get(&kid_url).send().await {
                                            Ok(kid_resp) if kid_resp.status().is_success() => {
                                                if let Ok(kid_json) =
                                                    kid_resp.json::<serde_json::Value>().await
                                                {
                                                    let mut matched = false;
                                                    use base64::Engine;
                                                    let expected_pubkey = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(domain_record.pubkey());

                                                    if let Some(keys) =
                                                        kid_json["kid_document"]["controller_keys"]
                                                            .as_array()
                                                    {
                                                        for key in keys {
                                                            if key["public_key"].as_str()
                                                                == Some(&expected_pubkey)
                                                            {
                                                                matched = true;
                                                                break;
                                                            }
                                                        }
                                                    }
                                                    if !matched {
                                                        warn!(
                                                            "E2E Auth Failed: Record pubkey does not match authorized KID {}",
                                                            did
                                                        );
                                                        let response = builder.error_msg(request.header(), hickory_proto::op::ResponseCode::ServFail);
                                                        let _ = response_handle
                                                            .send_response(response)
                                                            .await;
                                                        header.set_response_code(hickory_proto::op::ResponseCode::ServFail);
                                                        return header.into();
                                                    } else {
                                                        info!(
                                                            "E2E Auth Successful: Record pubkey matches Authorized KID {}",
                                                            did
                                                        );
                                                    }
                                                }
                                            }
                                            Ok(resp) => {
                                                warn!(
                                                    "E2E Auth: Daemon returned {} for KID {}",
                                                    resp.status(),
                                                    did
                                                );
                                                let response = builder.error_msg(
                                                    request.header(),
                                                    hickory_proto::op::ResponseCode::ServFail,
                                                );
                                                let _ =
                                                    response_handle.send_response(response).await;
                                                header.set_response_code(
                                                    hickory_proto::op::ResponseCode::ServFail,
                                                );
                                                return header.into();
                                            }
                                            Err(e) => {
                                                warn!("E2E Auth Request failed: {}", e);
                                                let response = builder.error_msg(
                                                    request.header(),
                                                    hickory_proto::op::ResponseCode::ServFail,
                                                );
                                                let _ =
                                                    response_handle.send_response(response).await;
                                                header.set_response_code(
                                                    hickory_proto::op::ResponseCode::ServFail,
                                                );
                                                return header.into();
                                            }
                                        }
                                    }
                                }
                            }

                            let subdomain = if domain_name == apex_domain {
                                "@".to_string()
                            } else {
                                let mut sub = domain_name
                                    .trim_end_matches(&format!(".{}", apex_domain))
                                    .to_string();
                                if sub.ends_with('.') {
                                    sub.pop();
                                }
                                if sub.is_empty() { "@".to_string() } else { sub }
                            };

                            if let Some(records) = zone
                                .records
                                .get(&subdomain)
                                .or_else(|| zone.records.get("*"))
                            {
                                let name = match Name::from_str(query_name) {
                                    Ok(n) => n,
                                    Err(e) => {
                                        error!("Invalid query name format: {}", e);
                                        let response = builder.error_msg(
                                            request.header(),
                                            hickory_proto::op::ResponseCode::FormErr,
                                        );
                                        let _ = response_handle.send_response(response).await;
                                        header.set_response_code(
                                            hickory_proto::op::ResponseCode::FormErr,
                                        );
                                        return header.into();
                                    }
                                };
                                let q_type = query.query_type();
                                let mut response_records = Vec::new();

                                // To respect Web2 RFCs at the DNS edge, if a CNAME exists, it must be the ONLY record returned.
                                // We filter out the KID (and anything else) for Web2 OS resolvers.
                                let has_cname = records
                                    .iter()
                                    .any(|r| matches!(r, kinetic_core::types::DnsRecord::CNAME(_)));

                                for record in records {
                                    if has_cname
                                        && !matches!(
                                            record,
                                            kinetic_core::types::DnsRecord::CNAME(_)
                                        )
                                    {
                                        continue; // Only return CNAME to legacy Web2 resolvers
                                    }
                                    match record {
                                        kinetic_core::types::DnsRecord::A(ip)
                                            if q_type == hickory_proto::rr::RecordType::A =>
                                        {
                                            if !kinetic_core::net::is_ssrf_safe(
                                                std::net::IpAddr::V4(*ip),
                                            ) {
                                                warn!(
                                                    "Blocked SSRF attempt: A record points to forbidden IP {}",
                                                    ip
                                                );
                                                continue;
                                            }
                                            response_records.push(Record::from_rdata(
                                                name.clone(),
                                                60,
                                                RData::A((*ip).into()),
                                            ));
                                        }
                                        kinetic_core::types::DnsRecord::AAAA(ip)
                                            if q_type == hickory_proto::rr::RecordType::AAAA =>
                                        {
                                            if !kinetic_core::net::is_ssrf_safe(
                                                std::net::IpAddr::V6(*ip),
                                            ) {
                                                warn!(
                                                    "Blocked SSRF attempt: AAAA record points to forbidden IP {}",
                                                    ip
                                                );
                                                continue;
                                            }
                                            response_records.push(Record::from_rdata(
                                                name.clone(),
                                                60,
                                                RData::AAAA((*ip).into()),
                                            ));
                                        }
                                        kinetic_core::types::DnsRecord::CNAME(target) => {
                                            // By DNS RFC, a CNAME should be returned regardless of what the user asked for (A/AAAA/TXT).
                                            // The OS resolver will receive the CNAME and recursively follow it.

                                            let target_lower = target.to_lowercase();
                                            let mut is_blocked_cname = false;

                                            for &blocked_name in
                                                kinetic_core::types::names::PUBLIC_NAMES
                                            {
                                                if target_lower == blocked_name
                                                    || target_lower
                                                        .ends_with(&format!(".{}", blocked_name))
                                                {
                                                    is_blocked_cname = true;
                                                    break;
                                                }
                                            }

                                            if is_blocked_cname {
                                                warn!(
                                                    "Blocked SSRF attempt: CNAME record points to forbidden local/internal domain {}",
                                                    target
                                                );
                                                continue;
                                            }

                                            if let Ok(ip) = target.parse::<std::net::IpAddr>()
                                                && !kinetic_core::net::is_ssrf_safe(ip)
                                            {
                                                warn!(
                                                    "Blocked SSRF attempt: CNAME record points to forbidden IP {}",
                                                    ip
                                                );
                                                continue;
                                            }

                                            if let Ok(cname) = Name::from_str(target) {
                                                response_records.push(Record::from_rdata(
                                                    name.clone(),
                                                    60,
                                                    RData::CNAME(hickory_proto::rr::rdata::CNAME(
                                                        cname,
                                                    )),
                                                ));
                                            }
                                        }
                                        kinetic_core::types::DnsRecord::TXT(txt)
                                            if q_type == hickory_proto::rr::RecordType::TXT
                                                || q_type == hickory_proto::rr::RecordType::ANY =>
                                        {
                                            response_records.push(Record::from_rdata(
                                                name.clone(),
                                                60,
                                                RData::TXT(hickory_proto::rr::rdata::TXT::new(
                                                    vec![txt.clone()],
                                                )),
                                            ));
                                        }
                                        kinetic_core::types::DnsRecord::PeerId(pid)
                                            if q_type == hickory_proto::rr::RecordType::TXT
                                                || q_type == hickory_proto::rr::RecordType::ANY =>
                                        {
                                            response_records.push(Record::from_rdata(
                                                name.clone(),
                                                60,
                                                RData::TXT(hickory_proto::rr::rdata::TXT::new(
                                                    vec![format!("peerid={}", pid)],
                                                )),
                                            ));
                                        }
                                        kinetic_core::types::DnsRecord::KID(kid)
                                            if q_type == hickory_proto::rr::RecordType::TXT
                                                || q_type == hickory_proto::rr::RecordType::ANY =>
                                        {
                                            response_records.push(Record::from_rdata(
                                                name.clone(),
                                                60,
                                                RData::TXT(hickory_proto::rr::rdata::TXT::new(
                                                    vec![format!("kid={}", kid)],
                                                )),
                                            ));
                                        }
                                        kinetic_core::types::DnsRecord::IPFS(cid)
                                            if q_type == hickory_proto::rr::RecordType::TXT
                                                || q_type == hickory_proto::rr::RecordType::ANY =>
                                        {
                                            response_records.push(Record::from_rdata(
                                                name.clone(),
                                                60,
                                                RData::TXT(hickory_proto::rr::rdata::TXT::new(
                                                    vec![format!("ipfs={}", cid)],
                                                )),
                                            ));
                                        }
                                        _ => {}
                                    }
                                }

                                if !response_records.is_empty() {
                                    header.set_response_code(
                                        hickory_proto::op::ResponseCode::NoError,
                                    );
                                    let response = builder.build(
                                        header,
                                        response_records.iter(),
                                        std::iter::empty(),
                                        std::iter::empty(),
                                        std::iter::empty(),
                                    );
                                    let _ = response_handle.send_response(response).await;
                                    return header.into();
                                }
                            } else {
                                warn!("No records found for subdomain: {}", subdomain);
                            }
                        }
                        Err(e) => warn!("Payload was not a valid DnsZone: {}", e),
                    }
                }
                Err(e) => warn!("Payload was not a valid NameRecord: {}", e),
            }
        }
        Ok(None) => warn!("No payload found for .kin query (NXDOMAIN cached)"),
        Err(e) => {
            error!("Error resolving .kin query via DHT/Cache: {:?}", e);
            let response =
                builder.error_msg(request.header(), hickory_proto::op::ResponseCode::ServFail);
            let _ = response_handle.send_response(response).await;
            header.set_response_code(hickory_proto::op::ResponseCode::ServFail);
            return header.into();
        }
    }

    // No matching records found after a successful resolution — return NXDOMAIN.
    let response = builder.error_msg(request.header(), hickory_proto::op::ResponseCode::NXDomain);
    let _ = response_handle.send_response(response).await;
    header.set_response_code(hickory_proto::op::ResponseCode::NXDomain);
    header.into()
}
