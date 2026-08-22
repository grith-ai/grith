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
    // Subscribed BEFORE the upgrade completes, so a shutdown broadcast that
    // fires while the handshake is in flight is still observed rather than
    // missed by a receiver that did not exist yet.
    let shutdown = state.shutdown_tx.as_ref().map(broadcast::Sender::subscribe);
    ws.on_upgrade(move |socket| handle_ws_connection(socket, state.ws_tx.subscribe(), shutdown))
}

/// Resolve when the daemon starts shutting down; never, when this server has
/// no shutdown channel (tests, embedded uses).
///
/// Every receive outcome counts as shutdown: `Ok` is the signal itself,
/// `Lagged` means the signal was missed but sent, and `Closed` means the
/// sender side is gone — a daemon that no longer exists is as shut down as
/// one that said so.
async fn shutdown_signalled(rx: &mut Option<broadcast::Receiver<()>>) {
    match rx {
        Some(rx) => {
            let _ = rx.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// Handle a single WebSocket connection.
///
/// The shutdown arm ends the connection deliberately instead of letting the
/// TCP stream die with the process: the browser receives a proper Close
/// frame the moment shutdown begins, so the dashboard's reconnect logic gets
/// a clean signal and starts polling for the successor daemon immediately,
/// rather than discovering a dead socket on its next send.
async fn handle_ws_connection(
    mut socket: WebSocket,
    mut rx: broadcast::Receiver<String>,
    mut shutdown: Option<broadcast::Receiver<()>>,
) {
    tracing::info!("WebSocket client connected");

    loop {
        tokio::select! {
            // Daemon shutting down: tell the browser (it will reconnect to
            // the successor) and end the connection so graceful shutdown can
            // complete.
            _ = shutdown_signalled(&mut shutdown) => {
                let _ = socket.send(Message::Close(None)).await;
                tracing::info!("WebSocket client closed for daemon shutdown");
                break;
            }
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

    /// The arm that ends a WS connection at daemon shutdown must fire on the
    /// signal AND on a dropped sender, and must never fire for a server with
    /// no shutdown channel.
    #[tokio::test]
    async fn shutdown_signalled_resolves_on_signal_and_sender_drop_only() {
        let quick = std::time::Duration::from_millis(50);

        // No channel: pends forever (embedded/test servers never shut down
        // connections from under their callers).
        let mut none = None;
        assert!(
            tokio::time::timeout(quick, shutdown_signalled(&mut none))
                .await
                .is_err(),
            "no shutdown channel must mean no shutdown signal"
        );

        // The signal itself.
        let (tx, rx) = broadcast::channel::<()>(1);
        let mut some = Some(rx);
        let _ = tx.send(());
        tokio::time::timeout(quick, shutdown_signalled(&mut some))
            .await
            .expect("a sent shutdown must resolve the wait");

        // Sender gone entirely: a daemon that no longer exists counts too.
        let (tx, rx) = broadcast::channel::<()>(1);
        let mut some = Some(rx);
        drop(tx);
        tokio::time::timeout(quick, shutdown_signalled(&mut some))
            .await
            .expect("a dropped sender must resolve the wait");
    }

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
