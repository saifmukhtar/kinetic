use libp2p::request_response::{Event, Message};
use kinetic_types::action::{ActionSyncRequest, ActionSyncResponse};
use tracing::{debug, info};

/// Handle inbound ActionSync protocol events
pub async fn handle(
    swarm: &mut crate::event_loop::core::NetworkEventLoop,
    event: Event<ActionSyncRequest, ActionSyncResponse>,
) {
    match event {
        Event::Message { peer, message, .. } => match message {
            Message::Request { channel, .. } => {
                debug!("Received ActionSyncRequest from peer {:?}", peer);
                let response = ActionSyncResponse { actions: swarm.action_log.clone() };
                let _ = swarm.swarm.behaviour_mut().action_sync.send_response(channel, response);
            }
            Message::Response { request_id, response } => {
                if let Some(responder) = swarm.pending_action_sync_requests.remove(&request_id) {
                    let _ = responder.send(Ok(response));
                }
            }
        },
        Event::OutboundFailure { peer, request_id, error, .. } => {
            debug!("ActionSync outbound failure to peer {:?}: {:?}", peer, error);
            if let Some(responder) = swarm.pending_action_sync_requests.remove(&request_id) {
                let _ = responder.send(Err(crate::client::types::ProxyError::Other(std::borrow::Cow::Owned(error.to_string()))));
            }
        }
        Event::InboundFailure { peer, error, .. } => {
            debug!("ActionSync inbound failure from peer {:?}: {:?}", peer, error);
        }
        Event::ResponseSent { peer, .. } => {
            debug!("ActionSyncResponse successfully sent to peer {:?}", peer);
        }
    }
}
