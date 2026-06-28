use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_resolver::{TokioAsyncResolver, config::{ResolverConfig, ResolverOpts}};
use hickory_proto::rr::{Record, RData, Name};
use tracing::{info, warn, error};
use kinetic_network::NetworkClient;
use std::str::FromStr;

use moka::future::Cache;
use moka::Expiry;
use std::time::{Duration, Instant};
use std::sync::Arc;

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
    network: NetworkClient,
    resolver: TokioAsyncResolver,
    cache: Cache<String, Option<Vec<u8>>>,
}

impl KineticDnsHandler {
    pub fn new(network: NetworkClient) -> Self {
        // Use Cloudflare 1.1.1.1 DoH (DNS-over-HTTPS) for encrypted upstream proxy resolution
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare_https(), ResolverOpts::default());
        
        // Initialize moka cache for caching DHT resolves and preventing request stampedes
        let cache = Cache::builder()
            .expire_after(KineticExpiry)
            .build();
            
        Self { network, resolver, cache }
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
        
        if clean_name.ends_with(".kin") {
            let domain_name = kinetic_core::types::normalize_name(&clean_name);
            let apex_domain = kinetic_core::types::extract_apex_domain(&domain_name);
            
            let network_clone = self.network.clone();
            
            // `try_get_with` provides cache stampede protection natively!
            let apex_domain_clone = apex_domain.clone();
            let cache_result = self.cache.try_get_with(apex_domain.clone(), async move {
                // If it's a cache miss, we hit the DHT.
                info!("Cache miss for apex: {}. Hitting DHT...", apex_domain_clone);
                // `moka::try_get_with` requires the error type to be cloneable or put in an Arc
                network_clone.resolve_redundant_payload(&apex_domain_clone).await.map_err(|e| Arc::new(e))
            }).await;

            match cache_result {
                Ok(Some(payload_bytes)) => {
                    info!("Successfully resolved .kin from Cache/DHT");
                    
                    // Robustly handle parsing errors to prevent crashes on bad DHT data
                    match serde_json::from_slice::<kinetic_core::types::Reveal>(&payload_bytes) {
                        Ok(reveal) => {
                            match kinetic_core::types::DnsZone::parse_payload(&reveal.payload) {
                                Ok(zone) => {
                                    let subdomain = if domain_name == apex_domain {
                                        "@".to_string()
                                    } else {
                                        let mut sub = domain_name.trim_end_matches(&format!(".{}", apex_domain)).to_string();
                                        if sub.ends_with('.') {
                                            sub.pop();
                                        }
                                        if sub.is_empty() {
                                            "@".to_string()
                                        } else {
                                            sub
                                        }
                                    };

                                    if let Some(records) = zone.records.get(&subdomain) {
                                        let name = match Name::from_str(&query_name) {
                                            Ok(n) => n,
                                            Err(e) => {
                                                error!("Invalid query name format: {}", e);
                                                let response = builder.error_msg(request.header(), hickory_proto::op::ResponseCode::FormErr);
                                                let _ = response_handle.send_response(response).await;
                                                header.set_response_code(hickory_proto::op::ResponseCode::FormErr);
                                                return header.into();
                                            }
                                        };
                                        let q_type = query.query_type();
                                        let mut response_records = Vec::new();

                                        for record in records {
                                            match record {
                                                kinetic_core::types::DnsRecord::A(ip) if q_type == hickory_proto::rr::RecordType::A => {
                                                    if let Ok(ipv4) = std::net::Ipv4Addr::from_str(ip) {
                                                        response_records.push(Record::from_rdata(name.clone(), 60, RData::A(ipv4.into())));
                                                    }
                                                }
                                                kinetic_core::types::DnsRecord::AAAA(ip) if q_type == hickory_proto::rr::RecordType::AAAA => {
                                                    if let Ok(ipv6) = std::net::Ipv6Addr::from_str(ip) {
                                                        response_records.push(Record::from_rdata(name.clone(), 60, RData::AAAA(ipv6.into())));
                                                    }
                                                }
                                                kinetic_core::types::DnsRecord::CNAME(target) if q_type == hickory_proto::rr::RecordType::CNAME => {
                                                    if let Ok(cname) = Name::from_str(target) {
                                                        response_records.push(Record::from_rdata(name.clone(), 60, RData::CNAME(hickory_proto::rr::rdata::CNAME(cname))));
                                                    }
                                                }
                                                kinetic_core::types::DnsRecord::TXT(txt) if q_type == hickory_proto::rr::RecordType::TXT => {
                                                    response_records.push(Record::from_rdata(name.clone(), 60, RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![txt.clone()]))));
                                                }
                                                _ => {}
                                            }
                                        }

                                        if !response_records.is_empty() {
                                            header.set_response_code(hickory_proto::op::ResponseCode::NoError);
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
                    let response = builder.error_msg(request.header(), hickory_proto::op::ResponseCode::ServFail);
                    let _ = response_handle.send_response(response).await;
                    header.set_response_code(hickory_proto::op::ResponseCode::ServFail);
                    return header.into();
                },
            }
            
            // If we fall through here, it means we didn't find any valid records or payload was malformed. NXDOMAIN.
            let response = builder.error_msg(request.header(), hickory_proto::op::ResponseCode::NXDomain);
            let _ = response_handle.send_response(response).await;
            header.set_response_code(hickory_proto::op::ResponseCode::NXDomain);
            
        } else {
            let name = match Name::from_str(&query_name) {
                Ok(n) => n,
                Err(e) => {
                    error!("Failed to parse query name: {}", e);
                    let response = builder.error_msg(request.header(), hickory_proto::op::ResponseCode::FormErr);
                    let _ = response_handle.send_response(response).await;
                    header.set_response_code(hickory_proto::op::ResponseCode::FormErr);
                    return header.into();
                }
            };
            
            match self.resolver.lookup(name, query.query_type()).await {
                Ok(lookup) => {
                    let records: Vec<Record> = lookup.record_iter().cloned().collect();
                    let response = builder.build(
                        header.clone(),
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
                        hickory_resolver::error::ResolveErrorKind::NoRecordsFound { .. } => hickory_proto::op::ResponseCode::NXDomain,
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
