// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! WebSocket live-stream endpoint for real-time proxy event broadcasting.

use crate::AppState;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use tokio::sync::broadcast;

/// WebSocket upgrade handler for `/ws/live`.
///
/// Authorization (Origin-vs-Host plus dashboard token when configured) is
/// enforced by the [`crate::ws_auth::require_ws_auth`] middleware layered on
/// this route, so a rejected handshake never reaches this handler.
pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_connection(socket, state.ws_tx.subscribe()))
}

/// Handle a single WebSocket connection.
async fn handle_ws_connection(mut socket: WebSocket, mut rx: broadcast::Receiver<String>) {
    tracing::info!("WebSocket client connected");

    loop {
        tokio::select! {
            // Forward broadcast messages to the WebSocket client
            msg = rx.recv() => {
                match msg {
                    Ok(text) => {
                        if socket.send(Message::Text(text)).await.is_err() {
                            break; // Client disconnected
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "WebSocket client lagged, skipping messages");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break; // Channel closed (server shutting down)
                    }
                }
            }
            // Handle incoming messages from the client (ping/pong, close)
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Ping(data))) => match socket.send(Message::Pong(data)).await {
                        Ok(()) => {}
                        Err(_) => break,
                    },
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {} // Ignore text/binary from client
                }
            }
        }
    }

    tracing::info!("WebSocket client disconnected");
}

/// Publish a proxy decision event to all connected WebSocket clients.
pub fn broadcast_event(tx: &broadcast::Sender<String>, event: &serde_json::Value) {
    if tx.receiver_count() > 0 {
        let msg = event.to_string();
        let _ = tx.send(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadcast_event_no_receivers() {
        let (tx, _rx) = broadcast::channel::<String>(16);
        // Drop the receiver
        drop(_rx);

        // Should not panic even with no receivers
        broadcast_event(
            &tx,
            &serde_json::json!({"type": "proxy_decision", "score": 2.5}),
        );
    }

    #[test]
    fn test_broadcast_event_with_receiver() {
        let (tx, mut rx) = broadcast::channel::<String>(16);
        broadcast_event(
            &tx,
            &serde_json::json!({"type": "proxy_decision", "score": 2.5}),
        );

        let msg = rx.try_recv().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(parsed["type"], "proxy_decision");
        assert_eq!(parsed["score"], 2.5);
    }
}
