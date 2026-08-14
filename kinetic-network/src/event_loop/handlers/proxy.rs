use crate::client::{ProxyRequest, ProxyResponse};
use crate::event_loop::core::NetworkEventLoop;
use libp2p::request_response::{Event, Message};

pub(crate) async fn handle(
    event_loop: &mut NetworkEventLoop,
    e: Event<ProxyRequest, ProxyResponse>,
) {
    match e {
        Event::Message { message, .. } => match message {
            Message::Request {
                request, channel, ..
            } => {
                if let Some(tx) = &event_loop.incoming_proxy_tx {
                    let tx_clone = tx.clone();
                    crate::event_loop::utils::spawn(async move {
                        let _ = tx_clone.send((request, channel)).await;
                    });
                }
            }
            Message::Response {
                request_id,
                response,
            } => {
                if let Some(responder) = event_loop.pending_proxy_requests.remove(&request_id) {
                    let _ = responder.send(Ok(response));
                }
            }
        },
        Event::OutboundFailure {
            request_id, error, ..
        } => {
            if let Some(responder) = event_loop.pending_proxy_requests.remove(&request_id) {
                use libp2p::request_response::OutboundFailure;
                let proxy_err = match error {
                    OutboundFailure::DialFailure => crate::client::ProxyError::Offline,
                    OutboundFailure::Timeout => crate::client::ProxyError::Timeout,
                    OutboundFailure::ConnectionClosed => {
                        crate::client::ProxyError::ConnectionClosed
                    }
                    OutboundFailure::UnsupportedProtocols => {
                        crate::client::ProxyError::UnsupportedProtocols
                    }
                    _ => crate::client::ProxyError::Other(format!("{:?}", error).into()),
                };
                let _ = responder.send(Err(proxy_err));
            }
        }
        _ => {}
    }
}
