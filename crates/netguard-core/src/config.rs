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
    #[serde(default = "MitmproxyConfig::default")]
    pub mitmproxy: MitmproxyConfig,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitmproxyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_mitm_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_mitm_listen_port")]
    pub listen_port: u16,
    #[serde(default = "default_mitm_socket_path")]
    pub socket_path: String,
    #[serde(default = "default_mitm_confdir")]
    pub confdir: String,
    #[serde(default = "default_mitm_uid_user")]
    pub uid_user: String,
    #[serde(default = "default_mitm_max_body_size")]
    pub max_body_size_bytes: usize,
    #[serde(default = "default_mitm_idle_timeout")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_true")]
    pub persist_bodies: bool,
    /// If false (default), the web UI cannot toggle mitmproxy at runtime.
    /// Enabling mitmproxy then requires editing this config file as root and
    /// restarting the daemon. Turn this on only if you trust everyone who
    /// holds the API token to be able to start a MITM proxy at will.
    #[serde(default)]
    pub allow_runtime_toggle: bool,
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
fn default_mitm_listen_addr() -> String { "127.0.0.1".into() }
fn default_mitm_listen_port() -> u16 { 8080 }
fn default_mitm_socket_path() -> String { "/run/netguard/mitm.sock".into() }
fn default_mitm_confdir() -> String { "/var/lib/netguard/mitm".into() }
fn default_mitm_uid_user() -> String { "netguard-mitm".into() }
fn default_mitm_max_body_size() -> usize { 1_048_576 }
fn default_mitm_idle_timeout() -> u64 { 10 }

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

impl Default for MitmproxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: default_mitm_listen_addr(),
            listen_port: default_mitm_listen_port(),
            socket_path: default_mitm_socket_path(),
            confdir: default_mitm_confdir(),
            uid_user: default_mitm_uid_user(),
            max_body_size_bytes: default_mitm_max_body_size(),
            idle_timeout_secs: default_mitm_idle_timeout(),
            persist_bodies: true,
            allow_runtime_toggle: false,
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
            mitmproxy: MitmproxyConfig::default(),
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

/// Resolve a system username to its numeric UID and primary GID using getpwnam.
///
/// Refuses empty names, names that don't resolve, and UID 0 (root). We allow
/// standard system UIDs (>=1) because dedicated service users created via
/// `useradd -r` are assigned UIDs in the 100-999 range by Debian/Ubuntu/Fedora
/// policy — rejecting them would make deploy.sh's `netguard-mitm` account
/// unusable. The residual risk (a legacy system UID being recycled) is
/// documented in the threat-model section of README.md.
#[cfg(target_os = "linux")]
pub fn resolve_system_user(name: &str) -> Result<(u32, u32), NetGuardError> {
    use std::ffi::CString;
    if name.is_empty() {
        return Err(NetGuardError::Config("mitmproxy uid_user is empty".into()));
    }
    let cname = CString::new(name)
        .map_err(|_| NetGuardError::Config(format!("mitmproxy uid_user '{name}' contains NUL")))?;
    let entry = unsafe { libc::getpwnam(cname.as_ptr()) };
    if entry.is_null() {
        return Err(NetGuardError::Config(format!(
            "mitmproxy uid_user '{name}' does not exist on this system"
        )));
    }
    let uid = unsafe { (*entry).pw_uid };
    let gid = unsafe { (*entry).pw_gid };
    if uid == 0 {
        return Err(NetGuardError::Config(format!(
            "mitmproxy uid_user '{name}' resolved to UID 0 (root). Refusing: installing an owner-match RETURN for root would bypass the firewall for every root process."
        )));
    }
    Ok((uid, gid))
}

#[cfg(not(target_os = "linux"))]
pub fn resolve_system_user(_name: &str) -> Result<(u32, u32), NetGuardError> {
    Err(NetGuardError::Config(
        "resolve_system_user is only implemented on Linux".into(),
    ))
}
