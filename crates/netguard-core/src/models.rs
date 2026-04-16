use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Other(n) => write!(f, "proto:{n}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub exe_path: String,
    pub cmdline: String,
    pub uid: u32,
    pub username: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Deny,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub process: Option<ProcessInfo>,
    pub verdict: Verdict,
    pub rule_id: Option<Uuid>,
    pub direction: Direction,
    pub hostname: Option<String>,
    /// Hex dump of first bytes of transport-layer payload (after IP+TCP/UDP headers)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_hex: Option<String>,
    /// Size of the full packet in bytes
    pub packet_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub enabled: bool,
    pub app_path: String,
    pub direction: Option<Direction>,
    pub remote_host: Option<String>,
    pub remote_port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub verdict: Verdict,
    pub temporary: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub hit_count: u64,
    pub last_hit: Option<DateTime<Utc>>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPrompt {
    pub id: Uuid,
    pub connection: Connection,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PromptResponse {
    pub prompt_id: Uuid,
    pub verdict: Verdict,
    pub remember: bool,
    pub scope: RuleScope,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleScope {
    ThisConnectionOnly,
    AppToDestination,
    AppToPort,
    AppAnywhere,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "snake_case")]
pub enum WsEvent {
    NewConnection(Connection),
    Prompt(PendingPrompt),
    PromptResolved {
        prompt_id: Uuid,
        verdict: Verdict,
    },
    RuleChanged(Rule),
    Stats(DashboardStats),
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct DashboardStats {
    pub active_connections: u64,
    pub total_allowed: u64,
    pub total_denied: u64,
    pub connections_per_second: f64,
    pub top_apps: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesFile {
    pub version: u32,
    pub rules: Vec<Rule>,
}

impl Default for RulesFile {
    fn default() -> Self {
        Self {
            version: 1,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CreateRuleRequest {
    pub app_path: String,
    pub direction: Option<Direction>,
    pub remote_host: Option<String>,
    pub remote_port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub verdict: Verdict,
    pub temporary: bool,
    pub duration_secs: Option<u64>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpdateRuleRequest {
    pub enabled: Option<bool>,
    pub app_path: Option<String>,
    pub direction: Option<Option<Direction>>,
    pub remote_host: Option<Option<String>>,
    pub remote_port: Option<Option<u16>>,
    pub protocol: Option<Option<Protocol>>,
    pub verdict: Option<Verdict>,
    pub note: Option<Option<String>>,
}
