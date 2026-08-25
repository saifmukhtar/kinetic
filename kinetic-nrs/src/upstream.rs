//! Upstream OS DNS resolver creation and DoH fallback resolution proxy.

use hickory_proto::rr::{Name, Record};
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::{
    TokioAsyncResolver,
    config::{ResolverConfig, ResolverOpts},
};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, ResponseHandler, ResponseInfo};
use std::str::FromStr;
use tracing::{error, warn};

/// Creates a new [`TokioAsyncResolver`] initialized with the operating system's native DNS configuration.
///
/// If reading the OS `/etc/resolv.conf` or Windows registry fails, it gracefully falls back to Cloudflare DNS-over-HTTPS (`1.1.1.1`).
pub fn create_resolver() -> TokioAsyncResolver {
    let (config, opts) = read_system_conf().unwrap_or_else(|e| {
        tracing::warn!(
            error_code = "KIN-NRS-017",
            "Failed to read OS DNS config ({}). Falling back to Cloudflare 1.1.1.1",
            e
        );
        (ResolverConfig::cloudflare_https(), ResolverOpts::default())
    });
    TokioAsyncResolver::tokio(config, opts)
}

/// Creates a new [`TokioAsyncResolver`] configured strictly to query the local kinetic-atlas bridge daemon.
pub fn create_atlas_resolver(port: u16) -> TokioAsyncResolver {
    let mut config = ResolverConfig::new();
    let socket = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        port,
    );
    config.add_name_server(hickory_resolver::config::NameServerConfig::new(
        socket,
        hickory_resolver::config::Protocol::Udp,
    ));
    config.add_name_server(hickory_resolver::config::NameServerConfig::new(
        socket,
        hickory_resolver::config::Protocol::Tcp,
    ));

    let opts = ResolverOpts::default();
    TokioAsyncResolver::tokio(config, opts)
}

/// Proxies a non-`.kin` DNS query (e.g. `.com`, `.org`) to the upstream resolver.
///
/// Sends the resolved record set or appropriate RCode (`NXDomain`, `FormErr`, `ServFail`) back to the client.
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
            error!(error_code = "KIN-NRS-018", "Failed to parse query name: {}", e);
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
            warn!(error_code = "KIN-NRS-019", "Upstream resolve error: {}", e);
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
