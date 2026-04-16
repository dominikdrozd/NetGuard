use netguard_core::connection_log::ConnectionLog;
use netguard_core::models::*;
use netguard_core::rule_engine::RuleEngine;
use netguard_mitm::MitmProxyController;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc, RwLock};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    /// Rule engine behind std::sync::RwLock (shared with NFQUEUE OS thread)
    pub rule_engine: Arc<std::sync::RwLock<RuleEngine>>,
    pub connection_log: Arc<ConnectionLog>,
    pub pending_prompts: Arc<RwLock<HashMap<Uuid, PendingPrompt>>>,
    pub prompt_response_tx: mpsc::Sender<PromptResponse>,
    pub ws_broadcast_tx: broadcast::Sender<WsEvent>,
    pub api_token: String,
    pub listen_port: u16,
    /// Rate limiting: timestamps of failed auth attempts (last 60s)
    pub auth_attempts: Arc<Mutex<Vec<std::time::Instant>>>,
    /// One-time WebSocket tickets (ticket_id -> expiry)
    pub ws_tickets: Arc<Mutex<HashMap<String, std::time::Instant>>>,
    /// Runtime mitmproxy controller (bridge lifecycle + iptables REDIRECT)
    pub mitm_controller: Arc<MitmProxyController>,
}
