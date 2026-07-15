use hickory_proto::rr::{Name, Record};
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, ResponseHandler, ResponseInfo};
use std::str::FromStr;
use tracing::{error, warn};

/// Creates a new `TokioAsyncResolver` using the system's DNS configuration,
/// falling back to Cloudflare DNS-over-HTTPS if the system config cannot be read.
pub fn create_resolver() -> TokioAsyncResolver {
    let (config, opts) = read_system_conf().unwrap_or_else(|e| {
        tracing::warn!(
            "Failed to read OS DNS config ({}). Falling back to Cloudflare 1.1.1.1",
            e
        );
        (ResolverConfig::cloudflare_https(), ResolverOpts::default())
    });
    TokioAsyncResolver::tokio(config, opts)
}

/// Proxies a DNS request to the upstream resolver and streams the response back to the client.
pub async fn resolve_upstream<R: ResponseHandler>(
    resolver: &TokioAsyncResolver,
    request: &Request,
    mut response_handle: R,
    query_name: &str,
    mut header: hickory_proto::op::Header,
    builder: MessageResponseBuilder<'_>,
) -> ResponseInfo {
    let query = request.query();

    let name = match Name::from_str(query_name) {
        Ok(n) => n,
        Err(e) => {
            error!("Failed to parse query name: {}", e);
            let response =
                builder.error_msg(request.header(), hickory_proto::op::ResponseCode::FormErr);
            let _ = response_handle.send_response(response).await;
            header.set_response_code(hickory_proto::op::ResponseCode::FormErr);
            return header.into();
        }
    };

    match resolver.lookup(name, query.query_type()).await {
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
            header.into()
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
            header.into()
        }
    }
}
