use libp2p::request_response::{Event, Message};
use kinetic_types::action::{GovSyncRequest, GovSyncResponse};
use tracing::{debug, info};

/// Handle inbound GovSync protocol events
pub async fn handle(
    swarm: &mut crate::event_loop::core::NetworkEventLoop,
    event: Event<GovSyncRequest, GovSyncResponse>,
) {
    match event {
        Event::Message { peer, message, .. } => match message {
            Message::Request { channel, .. } => {
                debug!("Received GovSyncRequest from peer {:?}", peer);
                let response = GovSyncResponse { actions: swarm.action_log.clone() };
                let _ = swarm.swarm.behaviour_mut().gov_sync.send_response(channel, response);
            }
            Message::Response { request_id, response } => {
                if let Some(responder) = swarm.pending_gov_sync_requests.remove(&request_id) {
                    let _ = responder.send(Ok(response));
                }
            }
        },
        Event::OutboundFailure { peer, request_id, error, .. } => {
            debug!("GovSync outbound failure to peer {:?}: {:?}", peer, error);
            if let Some(responder) = swarm.pending_gov_sync_requests.remove(&request_id) {
                let _ = responder.send(Err(crate::client::types::ProxyError::Other(std::borrow::Cow::Owned(error.to_string()))));
            }
        }
        Event::InboundFailure { peer, error, .. } => {
            debug!("GovSync inbound failure from peer {:?}: {:?}", peer, error);
        }
        Event::ResponseSent { peer, .. } => {
            debug!("GovSyncResponse successfully sent to peer {:?}", peer);
        }
    }
}
