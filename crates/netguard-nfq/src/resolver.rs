use crate::queue::PacketEvent;
use netguard_core::connection_log::ConnectionLog;
use netguard_core::models::*;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Run the async event processor that logs connections and broadcasts to the UI.
/// Verdicts are already decided by the NFQUEUE thread -- this is logging/display only.
pub async fn run_event_processor(
    mut event_rx: tokio::sync::mpsc::Receiver<PacketEvent>,
    event_tx: broadcast::Sender<WsEvent>,
    connection_log: Arc<ConnectionLog>,
) {
    while let Some(event) = event_rx.recv().await {
        let conn = event.connection;

        // Broadcast to WebSocket clients
        let _ = event_tx.send(WsEvent::NewConnection(conn.clone()));

        // Log
        connection_log.push(conn).await;
    }

    tracing::info!("Event channel closed, event processor shutting down");
}
