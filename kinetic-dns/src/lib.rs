//! # kinetic-dns
//!
//! DNS resolution layer for the Kinetic `.kin` naming network.
//!
//! This crate implements a custom DNS request handler ([`KineticDnsHandler`])
//! using the [hickory-dns](https://crates.io/crates/hickory-server) library.
//! It intercepts DNS queries for `.kin` domains, resolves them against the
//! Kinetic daemon's HTTP API (which in turn queries the Kademlia DHT), and
//! proxies all other queries to Cloudflare 1.1.1.1 via DNS-over-HTTPS.
//!
//! ## Caching
//!
//! Resolved records are cached in-process using
//! [moka](https://crates.io/crates/moka) with asymmetric TTLs:
//!
//! - **Positive hits** (domain found): cached for 5 minutes.
//! - **Negative hits** (NXDOMAIN): cached for 30 seconds.
//!
//! Cache stampede protection is provided natively by moka's `try_get_with`.
//! The [`KineticDnsHandler::invalidate_cache`] method allows the daemon to
//! proactively evict a domain after a successful local update.

use hickory_proto::rr::{Name, RData, Record};
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use std::str::FromStr;
use tracing::{error, info, warn};

use moka::future::Cache;
use moka::Expiry;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct KineticExpiry;

impl Expiry<String, Option<Vec<u8>>> for KineticExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &Option<Vec<u8>>,
        _created_at: Instant,
    ) -> Option<Duration> {
        if value.is_some() {
            Some(Duration::from_secs(300)) // 5 minutes positive cache
        } else {
            Some(Duration::from_secs(30)) // 30 seconds negative cache (NXDOMAIN)
        }
    }

    fn expire_after_read(
        &self,
        _key: &String,
        _value: &Option<Vec<u8>>,
        _read_at: Instant,
        duration_until_expiry: Option<Duration>,
        _last_modified_at: Instant,
    ) -> Option<Duration> {
        duration_until_expiry // Do not extend TTL on read
    }

    fn expire_after_update(
        &self,
        _key: &String,
        value: &Option<Vec<u8>>,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        if value.is_some() {
            Some(Duration::from_secs(300))
        } else {
            Some(Duration::from_secs(30))
        }
    }
}

/// The custom DNS handler that intercepts `.kin` queries and routes them to the DHT.
/// Standard queries (e.g., .com, .org) are passed through to upstream resolvers.
#[derive(Clone)]
pub struct KineticDnsHandler {
    api_url: String,
    http_client: reqwest::Client,
    resolver: TokioAsyncResolver,
    cache: Cache<String, Option<Vec<u8>>>,
}

impl KineticDnsHandler {
    pub fn new(api_url: String) -> Self {
        // Use Cloudflare 1.1.1.1 DoH for encrypted upstream resolution of non-.kin domains.
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare_https(), ResolverOpts::default());

        let cache = Cache::builder().expire_after(KineticExpiry).build();
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            api_url,
            http_client,
            resolver,
            cache,
        }
    }

    /// Explicitly invalidate the DNS cache for a given apex domain.
    /// This is called by the daemon after a successful local update to prevent serving stale data.
    pub async fn invalidate_cache(&self, apex_domain: &str) {
        let domain_normalized = kinetic_core::types::extract_apex_domain(apex_domain);
        self.cache.invalidate(&domain_normalized).await;
        tracing::info!(
            "Invalidated DNS cache for apex domain: {}",
            domain_normalized
        );
    }
}

#[async_trait::async_trait]
impl RequestHandler for KineticDnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let query = request.query();
        let query_name = query.name().to_string();
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = *request.header();
        header.set_message_type(hickory_proto::op::MessageType::Response);

        let mut clean_name = query_name.to_lowercase();
        if clean_name.ends_with('.') {
            clean_name.pop();
        }

        if clean_name.ends_with(kinetic_core::types::DOT_TLD) {
            let domain_name = kinetic_core::types::normalize_name(&clean_name);
            let apex_domain = kinetic_core::types::extract_apex_domain(&domain_name);

            // Intercept Category 1 PUBLIC_NAMES
            let parts: Vec<&str> = apex_domain.split('.').collect();
            if !parts.is_empty() && kinetic_core::types::PUBLIC_NAMES.contains(&parts[0]) {
                if parts[0] == "localhost" {
                    let mut response_records = Vec::new();
                    let name = Name::from_str(&query_name).unwrap_or_else(|_| Name::root());
                    
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
                    let response = builder.error_msg(request.header(), hickory_proto::op::ResponseCode::NXDomain);
                    let _ = response_handle.send_response(response).await;
                    header.set_response_code(hickory_proto::op::ResponseCode::NXDomain);
                    return header.into();
                }
            }

            let api_url_clone = self.api_url.clone();
            let http_client_clone = self.http_client.clone();
            let apex_domain_clone = apex_domain.clone();

            let cache_result = self
                .cache
                .try_get_with(apex_domain.clone(), async move {
                    // Cache miss: hit the daemon API to resolve from the DHT.
                    info!(
                        "Cache miss for apex: {}. Hitting daemon API...",
                        apex_domain_clone
                    );

                    let url = format!("{}/api/resolve/{}", api_url_clone, apex_domain_clone);
                    match http_client_clone.get(&url).send().await {
                        Ok(resp) => {
                            if resp.status().is_success() {
                                if let Ok(payload) = resp.bytes().await {
                                    Ok::<_, Arc<anyhow::Error>>(Some(payload.to_vec()))
                                } else {
                                    Err(Arc::new(anyhow::anyhow!(
                                        "Failed to read API response body"
                                    )))
                                }
                            } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
                                Ok(None)
                            } else {
                                Err(Arc::new(anyhow::anyhow!(
                                    "API returned status: {}",
                                    resp.status()
                                )))
                            }
                        }
                        Err(e) => Err(Arc::new(anyhow::anyhow!("API request failed: {}", e))),
                    }
                })
                .await;

            match cache_result {
                Ok(Some(payload_bytes)) => {
                    info!("Successfully resolved .kin from Cache/DHT");

                    match serde_json::from_slice::<kinetic_core::types::Reveal>(&payload_bytes) {
                        Ok(reveal) => {
                            match kinetic_core::types::DnsZone::parse_payload(&reveal.payload) {
                                Ok(zone) => {
                                    let subdomain = if domain_name == apex_domain {
                                        "@".to_string()
                                    } else {
                                        let mut sub = domain_name
                                            .trim_end_matches(&format!(".{}", apex_domain))
                                            .to_string();
                                        if sub.ends_with('.') {
                                            sub.pop();
                                        }
                                        if sub.is_empty() {
                                            "@".to_string()
                                        } else {
                                            sub
                                        }
                                    };

                                    if let Some(records) = zone
                                        .records
                                        .get(&subdomain)
                                        .or_else(|| zone.records.get("*"))
                                    {
                                        let name = match Name::from_str(&query_name) {
                                            Ok(n) => n,
                                            Err(e) => {
                                                error!("Invalid query name format: {}", e);
                                                let response = builder.error_msg(
                                                    request.header(),
                                                    hickory_proto::op::ResponseCode::FormErr,
                                                );
                                                let _ =
                                                    response_handle.send_response(response).await;
                                                header.set_response_code(
                                                    hickory_proto::op::ResponseCode::FormErr,
                                                );
                                                return header.into();
                                            }
                                        };
                                        let q_type = query.query_type();
                                        let mut response_records = Vec::new();

                                        for record in records {
                                            match record {
                                                kinetic_core::types::DnsRecord::A(ip)
                                                    if q_type
                                                        == hickory_proto::rr::RecordType::A =>
                                                {
                                                    response_records.push(Record::from_rdata(
                                                        name.clone(),
                                                        60,
                                                        RData::A((*ip).into()),
                                                    ));
                                                }
                                                kinetic_core::types::DnsRecord::AAAA(ip)
                                                    if q_type
                                                        == hickory_proto::rr::RecordType::AAAA =>
                                                {
                                                    response_records.push(Record::from_rdata(
                                                        name.clone(),
                                                        60,
                                                        RData::AAAA((*ip).into()),
                                                    ));
                                                }
                                                kinetic_core::types::DnsRecord::CNAME(target)
                                                    if q_type
                                                        == hickory_proto::rr::RecordType::CNAME =>
                                                {
                                                    if let Ok(cname) = Name::from_str(target) {
                                                        response_records.push(Record::from_rdata(
                                                            name.clone(),
                                                            60,
                                                            RData::CNAME(
                                                                hickory_proto::rr::rdata::CNAME(
                                                                    cname,
                                                                ),
                                                            ),
                                                        ));
                                                    }
                                                }
                                                kinetic_core::types::DnsRecord::TXT(txt)
                                                    if q_type
                                                        == hickory_proto::rr::RecordType::TXT =>
                                                {
                                                    response_records.push(Record::from_rdata(
                                                        name.clone(),
                                                        60,
                                                        RData::TXT(
                                                            hickory_proto::rr::rdata::TXT::new(
                                                                vec![txt.clone()],
                                                            ),
                                                        ),
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
                        Err(e) => warn!("Payload was not a valid Reveal tuple: {}", e),
                    }
                }
                Ok(None) => warn!("No payload found for .kin query (NXDOMAIN cached)"),
                Err(e) => {
                    error!("Error resolving .kin query via DHT/Cache: {:?}", e);
                    let response = builder
                        .error_msg(request.header(), hickory_proto::op::ResponseCode::ServFail);
                    let _ = response_handle.send_response(response).await;
                    header.set_response_code(hickory_proto::op::ResponseCode::ServFail);
                    return header.into();
                }
            }

            // No matching records found after a successful resolution — return NXDOMAIN.
            let response =
                builder.error_msg(request.header(), hickory_proto::op::ResponseCode::NXDomain);
            let _ = response_handle.send_response(response).await;
            header.set_response_code(hickory_proto::op::ResponseCode::NXDomain);
        } else {
            let name = match Name::from_str(&query_name) {
                Ok(n) => n,
                Err(e) => {
                    error!("Failed to parse query name: {}", e);
                    let response = builder
                        .error_msg(request.header(), hickory_proto::op::ResponseCode::FormErr);
                    let _ = response_handle.send_response(response).await;
                    header.set_response_code(hickory_proto::op::ResponseCode::FormErr);
                    return header.into();
                }
            };

            match self.resolver.lookup(name, query.query_type()).await {
                Ok(lookup) => {
                    let records: Vec<Record> = lookup.record_iter().cloned().collect();
                    let response = builder.build(
                        header,
                        records.iter(),
                        std::iter::empty(),
                        std::iter::empty(),
                        std::iter::empty(),
                    );
                    let _ = response_handle.send_response(response).await;
                    return header.into();
                }
                Err(e) => {
                    warn!("Upstream resolve error: {}", e);
                    let rcode = match e.kind() {
                        hickory_resolver::error::ResolveErrorKind::NoRecordsFound { .. } => {
                            hickory_proto::op::ResponseCode::NXDomain
                        }
                        _ => hickory_proto::op::ResponseCode::ServFail,
                    };
                    let response = builder.error_msg(request.header(), rcode);
                    let _ = response_handle.send_response(response).await;
                    header.set_response_code(rcode);
                    return header.into();
                }
            }
        }

        header.into()
    }
}

#[cfg(test)]
mod tests;
