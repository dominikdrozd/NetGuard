use crate::state::AppState;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;

/// Issue a one-time WebSocket ticket. Requires prior Bearer auth (via middleware).
/// Returns a short-lived ticket string the client uses to upgrade to WebSocket.
pub async fn issue_ws_ticket(
    State(state): State<AppState>,
) -> String {
    let ticket = uuid::Uuid::new_v4().to_string();
    let expiry = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut tickets = state.ws_tickets.lock().unwrap_or_else(|e| e.into_inner());
    // Clean expired tickets
    let now = std::time::Instant::now();
    tickets.retain(|_, exp| *exp > now);
    tickets.insert(ticket.clone(), expiry);
    ticket
}

#[derive(Deserialize)]
pub struct WsQuery {
    ticket: Option<String>,
}

pub async fn ws_handler(
    State(state): State<AppState>,
    Query(query): Query<WsQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, StatusCode> {
    // Validate one-time ticket (not the long-lived API token)
    let ticket = query.ticket.as_deref().unwrap_or("");
    let ticket_valid = {
        let mut tickets = state.ws_tickets.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        // Clean expired tickets on every WS upgrade attempt
        tickets.retain(|_, exp| *exp > now);
        if let Some(expiry) = tickets.remove(ticket) {
            expiry > now
        } else {
            false
        }
    };
    if !ticket_valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Validate Origin header (required -- reject if absent)
    let origin = headers.get("origin").and_then(|v| v.to_str().ok());
    match origin {
        Some(origin_str) => {
            let port = state.listen_port;
            let allowed = [
                format!("http://127.0.0.1:{port}"),
                format!("http://localhost:{port}"),
            ];
            if !allowed.iter().any(|a| a == origin_str) {
                tracing::warn!("WebSocket rejected: invalid origin {origin_str}");
                return Err(StatusCode::FORBIDDEN);
            }
        }
        None => {
            tracing::warn!("WebSocket rejected: missing Origin header");
            return Err(StatusCode::FORBIDDEN);
        }
    }

    Ok(ws.on_upgrade(move |socket| handle_ws(socket, state)))
}

async fn handle_ws(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();

    let mut broadcast_rx = state.ws_broadcast_tx.subscribe();

    let mut send_task = tokio::spawn(async move {
        loop {
            match broadcast_rx.recv().await {
                Ok(event) => {
                    if let Ok(json) = serde_json::to_string(&event) {
                        if sender.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::debug!("WebSocket client lagged, skipped {n} events");
                    continue;
                }
                Err(_) => break,
            }
        }
    });

    let state_clone = state.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
                    handle_client_message(&state_clone, &text).await;
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    // Wait for either task to finish, then abort the other
    tokio::select! {
        _ = &mut send_task => {
            recv_task.abort();
        },
        _ = &mut recv_task => {
            send_task.abort();
        },
    }
}

async fn handle_client_message(state: &AppState, text: &str) {
    #[derive(serde::Deserialize)]
    #[serde(tag = "type")]
    enum ClientMessage {
        #[serde(rename = "respond_prompt")]
        RespondPrompt {
            prompt_id: uuid::Uuid,
            verdict: netguard_core::models::Verdict,
            remember: bool,
            scope: netguard_core::models::RuleScope,
        },
    }

    if let Ok(msg) = serde_json::from_str::<ClientMessage>(text) {
        match msg {
            ClientMessage::RespondPrompt {
                prompt_id,
                verdict,
                remember,
                scope,
            } => {
                // Remove prompt from pending (same as HTTP path)
                let prompt = {
                    let mut prompts = state.pending_prompts.write().await;
                    prompts.remove(&prompt_id)
                };

                let Some(prompt) = prompt else {
                    tracing::debug!("WebSocket: ignoring response for unknown prompt {prompt_id}");
                    return;
                };

                let response = netguard_core::models::PromptResponse {
                    prompt_id,
                    verdict,
                    remember,
                    scope,
                };

                // Create rule if requested (same as HTTP path)
                if remember {
                    let mut engine = state
                        .rule_engine
                        .write()
                        .unwrap_or_else(|e| e.into_inner());
                    if let Some(rule) = engine.create_rule_from_prompt(&prompt.connection, &response)
                    {
                        let _ = state
                            .ws_broadcast_tx
                            .send(netguard_core::models::WsEvent::RuleChanged(rule));
                    }
                }

                // Broadcast resolution
                let _ = state
                    .ws_broadcast_tx
                    .send(netguard_core::models::WsEvent::PromptResolved {
                        prompt_id,
                        verdict,
                    });

                let _ = state.prompt_response_tx.send(response).await;
            }
        }
    }
}
