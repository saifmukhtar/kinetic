use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_resolver::{TokioAsyncResolver, config::{ResolverConfig, ResolverOpts}};
use hickory_proto::rr::{Record, RData, Name};
use tracing::{info, warn};
use kinetic_network::network::NetworkClient;
use std::str::FromStr;
use std::net::Ipv4Addr;

/// The custom DNS handler that intercepts `.kin` queries and routes them to the DHT.
/// Standard queries (e.g., .com, .org) are passed through to upstream resolvers.
#[derive(Clone)]
pub struct KineticDnsHandler {
    network: NetworkClient,
    resolver: TokioAsyncResolver,
}

impl KineticDnsHandler {
    pub fn new(network: NetworkClient) -> Self {
        // Use Cloudflare 1.1.1.1 as the upstream proxy resolver
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
        Self { network, resolver }
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
        
        if query_name.ends_with(".kin.") {
            info!("Intercepted Kinetic query: {}", query_name);
            match self.network.resolve_redundant_payload(&query_name).await {
                Ok(Some(payload_bytes)) => {
                    info!("Successfully resolved .kin from DHT");
                    
                    if let Ok(reveal) = serde_json::from_slice::<kinetic_core::types::Reveal>(&payload_bytes) {
                        if let Ok(ip_str) = String::from_utf8(reveal.payload) {
                        if let Ok(ip) = Ipv4Addr::from_str(&ip_str) {
                            let name = Name::from_str(&query_name).unwrap();
                            let record = Record::from_rdata(name, 60, RData::A(ip.into()));
                            // Set response code BEFORE sending the response
                            header.set_response_code(hickory_proto::op::ResponseCode::NoError);
                            let response = builder.build(
                                header,
                                std::iter::once(&record),
                                std::iter::empty(),
                                std::iter::empty(),
                                std::iter::empty(),
                            );
                            let _ = response_handle.send_response(response).await;
                            return header.into();
                        }
                        } else {
                            warn!("Payload was not a valid IPv4 address");
                        }
                    } else {
                        warn!("Payload was not a valid Reveal tuple");
                    }
                }
                Ok(None) => warn!("No payload found for .kin query"),
                Err(e) => warn!("Error resolving .kin query: {}", e),
            }
            
            let response = builder.error_msg(request.header(), hickory_proto::op::ResponseCode::NXDomain);
            let _ = response_handle.send_response(response).await;
            
        } else {
            let name = Name::from_str(&query_name).unwrap();
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
                }
                Err(e) => {
                    warn!("Upstream resolve error: {}", e);
                    let response = builder.error_msg(request.header(), hickory_proto::op::ResponseCode::ServFail);
                    let _ = response_handle.send_response(response).await;
                }
            }
        }
        
        // Fallthrough: return whatever response code header currently holds
        // (NXDomain if the .kin lookup failed, NoError if passthrough succeeded)
        header.into()
    }
}
