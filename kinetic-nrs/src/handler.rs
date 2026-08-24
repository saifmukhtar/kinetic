//! Hickory DNS RequestHandler implementation routing .kin queries to the DHT and standard queries to upstream resolvers.

use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};

use crate::KineticDnsHandler;
use crate::kinetic_records::resolve_kinetic;
use crate::upstream::resolve_upstream;

#[async_trait::async_trait]
impl RequestHandler for KineticDnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
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

        if clean_name.ends_with(kinetic_core::constants::NSP_SUFFIX) {
            let domain_name = kinetic_core::types::normalize_name(&clean_name);
            let apex_domain = kinetic_core::types::extract_apex_name(&domain_name);

            resolve_kinetic(
                request,
                response_handle,
                &query_name,
                header,
                builder,
                &domain_name,
                &apex_domain,
                &self.cache,
                &self.api_url,
                &self.http_client,
            )
            .await
        } else {
            let mut is_atlas = false;
            if let Ok(nsps) = self.atlas_nsps.read() {
                for nsp in nsps.iter() {
                    if clean_name == **nsp || clean_name.ends_with(&format!(".{}", nsp)) {
                        is_atlas = true;
                        break;
                    }
                }
            }

            if is_atlas {
                let atlas_resolver = {
                    self.atlas_resolver
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone()
                };
                resolve_upstream(
                    &atlas_resolver,
                    request,
                    response_handle,
                    &query_name,
                    header,
                    builder,
                )
                .await
            } else {
                let upstream_resolver = {
                    self.resolver
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone()
                };
                resolve_upstream(
                    &upstream_resolver,
                    request,
                    response_handle,
                    &query_name,
                    header,
                    builder,
                )
                .await
            }
        }
    }
}
