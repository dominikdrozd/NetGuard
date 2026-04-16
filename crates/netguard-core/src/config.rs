use crate::errors::NetGuardError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "DaemonConfig::default")]
    pub daemon: DaemonConfig,
    #[serde(default = "WebConfig::default")]
    pub web: WebConfig,
    #[serde(default = "RulesConfig::default")]
    pub rules: RulesConfig,
    #[serde(default = "LoggingConfig::default")]
    pub logging: LoggingConfig,
    #[serde(default = "NetworkConfig::default")]
    pub network: NetworkConfig,
    #[serde(default = "ProcConfig::default")]
    pub proc: ProcConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_queue_num")]
    pub queue_num: u16,
    #[serde(default = "default_verdict")]
    pub default_verdict: String,
    #[serde(default = "default_prompt_timeout")]
    pub prompt_timeout: u64,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_pid_file")]
    pub pid_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default = "default_auth_token_file")]
    pub auth_token_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    #[serde(default = "default_rules_file")]
    pub rules_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_file")]
    pub log_file: String,
    #[serde(default = "default_max_memory_entries")]
    pub max_memory_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_true")]
    pub intercept_outbound: bool,
    #[serde(default)]
    pub intercept_inbound: bool,
    #[serde(default = "default_true")]
    pub skip_loopback: bool,
    #[serde(default = "default_true")]
    pub skip_established: bool,
    #[serde(default)]
    pub fail_open: bool,
    #[serde(default)]
    pub whitelist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcConfig {
    #[serde(default = "default_cache_refresh_ms")]
    pub cache_refresh_ms: u64,
}

fn default_queue_num() -> u16 { 0 }
fn default_verdict() -> String { "deny".into() }
fn default_prompt_timeout() -> u64 { 15 }
fn default_log_level() -> String { "info".into() }
fn default_pid_file() -> String { "/var/run/netguard.pid".into() }
fn default_listen_addr() -> String { "127.0.0.1".into() }
fn default_listen_port() -> u16 { 3031 }
fn default_rules_file() -> String { "/etc/netguard/rules.json".into() }
fn default_log_file() -> String { "/var/log/netguard/connections.log".into() }
fn default_max_memory_entries() -> usize { 10000 }
fn default_cache_refresh_ms() -> u64 { 2000 }
fn default_true() -> bool { true }
fn default_auth_token_file() -> String { "/etc/netguard/api_token".into() }

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            queue_num: default_queue_num(),
            default_verdict: default_verdict(),
            prompt_timeout: default_prompt_timeout(),
            log_level: default_log_level(),
            pid_file: default_pid_file(),
        }
    }
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            listen_port: default_listen_port(),
            auth_token_file: default_auth_token_file(),
        }
    }
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            rules_file: default_rules_file(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_file: default_log_file(),
            max_memory_entries: default_max_memory_entries(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            intercept_outbound: true,
            intercept_inbound: false,
            skip_loopback: true,
            skip_established: true,
            fail_open: false,
            whitelist: Vec::new(),
        }
    }
}

impl Default for ProcConfig {
    fn default() -> Self {
        Self {
            cache_refresh_ms: default_cache_refresh_ms(),
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            daemon: DaemonConfig::default(),
            web: WebConfig::default(),
            rules: RulesConfig::default(),
            logging: LoggingConfig::default(),
            network: NetworkConfig::default(),
            proc: ProcConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self, NetGuardError> {
        let content = std::fs::read_to_string(path)?;
        let config: AppConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn rules_path(&self) -> PathBuf {
        PathBuf::from(&self.rules.rules_file)
    }
}
