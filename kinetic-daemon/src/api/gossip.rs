use axum::{
    Json,
    extract::{Path, State},
    response::sse::{Event, Sse},
};
use serde_json::Value;
use std::{convert::Infallible, time::Duration};
use tokio_stream::Stream;

use crate::api::{ApiState, PublishResponse};

/// Subscribes to a Gossipsub topic and streams live events via Server-Sent Events (SSE).
pub async fn handle_gossip_subscribe(
    Path(topic): Path<String>,
    State(state): State<ApiState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // We subscribe to the multiplexed broadcast channel
    let mut rx = state.gossip_tx.subscribe();

    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok((msg_topic, payload, _, _)) => {
                    if msg_topic == topic
                        && let Ok(payload_str) = String::from_utf8(payload) {
                            yield Ok(Event::default().data(payload_str));
                        }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    let err = kinetic_core::error::api::RestApiError::SseStreamLagged;
                    tracing::warn!(error_code = err.code(), "SSE subscriber lagged behind and skipped {} messages on topic {}", skipped, topic);
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

/// Broadcasts a JSON payload to a Gossipsub topic over the Kademlia network.
pub async fn handle_gossip_publish(
    axum::extract::Extension(role): axum::extract::Extension<crate::api::Role>,
    Path(topic): Path<String>,
    State(state): State<ApiState>,
    Json(payload): Json<Value>,
) -> Result<Json<PublishResponse>, crate::api::error::AppError> {
    if !role.can_publish() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }

    let payload_bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => {
            return Err(kinetic_core::error::PublishError::Internal {
                message: format!("Serialization failed: {}", e),
                source: None,
            }
            .into());
        }
    };

    if let Err(e) = state.network.broadcast_gossip(&topic, payload_bytes).await {
        return Err(e.into());
    }

    Ok(Json(PublishResponse {
        status: "success".to_string(),
        message: format!("Payload successfully broadcasted to topic: {}", topic),
    }))
}
