//! Runtime controller that owns the mitmproxy bridge lifecycle and the
//! associated iptables REDIRECT rules. The controller lets the web UI flip
//! HTTPS decryption on and off at runtime; the initial state comes from
//! `config.mitmproxy.enabled` at startup.
//!
//! iptables calls are inlined here (rather than importing from netguard-nfq)
//! so this crate stays free of Linux-only kernel-interface dependencies and
//! the web server can depend on it without pulling in the NFQUEUE stack.

use crate::{spawn_mitm_bridge, MitmBridgeConfig, MitmBridgeHandle, MitmFlowCache};
use std::process::Command;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Error)]
pub enum MitmError {
    #[error("mitmproxy runtime toggle is disabled in config")]
    ToggleDisabled,
    // Detail is kept in Display so operators see the full stderr/cmd text in
    // logs; `public_message()` below is the sanitized version returned to API
    // clients.
    #[error("iptables command failed: {0}")]
    Iptables(String),
    #[error("failed to spawn mitmproxy bridge: {0}")]
    Spawn(String),
    #[error("mitmproxy is not configured on this system: {0}")]
    NotConfigured(String),
}

impl MitmError {
    /// Short, user-safe message for API responses. Never includes internal
    /// paths, commands, or error text from subprocesses.
    pub fn public_message(&self) -> &'static str {
        match self {
            MitmError::ToggleDisabled => {
                "HTTPS decryption runtime toggle is disabled in netguard.toml"
            }
            MitmError::Iptables(_) => "failed to update firewall rules",
            MitmError::Spawn(_) => "failed to start mitmproxy",
            MitmError::NotConfigured(_) => "mitmproxy is not available on this system",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MitmControllerStatus {
    pub enabled: bool,
    pub listen_addr: String,
    pub listen_port: u16,
    pub ca_cert_path: String,
    pub ca_cert_installed: bool,
    pub allow_runtime_toggle: bool,
}

pub struct MitmProxyController {
    bridge_cfg: MitmBridgeConfig,
    flow_cache: Arc<MitmFlowCache>,
    state: Mutex<ControllerState>,
    ca_cert_path: String,
    allow_runtime_toggle: bool,
}

struct ControllerState {
    enabled: bool,
    bridge: Option<MitmBridgeHandle>,
    /// Port mitmdump is actually listening on. `None` while the bridge is
    /// disabled. Written by `enable()` on successful bridge start; cleared
    /// by `disable()`.
    bound_listen_port: Option<u16>,
}

impl MitmProxyController {
    /// Build a controller with a pre-sized flow cache. TTL is derived from
    /// the caller (typically `idle_timeout_secs * 2` so stale flows don't
    /// linger long after the resolver has given up waiting for them).
    pub fn new(
        bridge_cfg: MitmBridgeConfig,
        cache_ttl_secs: u64,
        allow_runtime_toggle: bool,
    ) -> Self {
        let ca_cert_path = bridge_cfg
            .confdir
            .join("mitmproxy-ca-cert.pem")
            .to_string_lossy()
            .to_string();
        Self {
            bridge_cfg,
            flow_cache: Arc::new(MitmFlowCache::new(cache_ttl_secs)),
            state: Mutex::new(ControllerState {
                enabled: false,
                bridge: None,
                bound_listen_port: None,
            }),
            ca_cert_path,
            allow_runtime_toggle,
        }
    }

    /// The flow cache is shared with the resolver so it can look up enriched
    /// flows. When the bridge is disabled, the cache just stays empty — the
    /// resolver's enrichment polling times out and drops the task.
    pub fn flow_cache(&self) -> Arc<MitmFlowCache> {
        self.flow_cache.clone()
    }

    pub async fn is_enabled(&self) -> bool {
        self.state.lock().await.enabled
    }

    pub fn allow_runtime_toggle(&self) -> bool {
        self.allow_runtime_toggle
    }

    pub async fn status(&self) -> MitmControllerStatus {
        let state = self.state.lock().await;
        let listen_port = state.bound_listen_port.unwrap_or(self.bridge_cfg.listen_port);
        MitmControllerStatus {
            enabled: state.enabled,
            listen_addr: self.bridge_cfg.listen_addr.clone(),
            listen_port,
            ca_cert_path: self.ca_cert_path.clone(),
            ca_cert_installed: tokio::fs::try_exists(&self.ca_cert_path)
                .await
                .unwrap_or(false),
            allow_runtime_toggle: self.allow_runtime_toggle,
        }
    }

    /// Enable called from the API path. Rejects if runtime toggle is disabled.
    pub async fn enable_via_toggle(&self) -> Result<(), MitmError> {
        if !self.allow_runtime_toggle {
            return Err(MitmError::ToggleDisabled);
        }
        self.enable().await
    }

    /// Disable called from the API path. Rejects if runtime toggle is disabled.
    pub async fn disable_via_toggle(&self) -> Result<(), MitmError> {
        if !self.allow_runtime_toggle {
            return Err(MitmError::ToggleDisabled);
        }
        self.disable().await
    }

    /// Spawn mitmdump and install the nat OUTPUT REDIRECT rules. Idempotent.
    /// Called unconditionally from daemon startup when config.mitmproxy.enabled=true;
    /// the runtime-toggle path goes through `enable_via_toggle()`.
    pub async fn enable(&self) -> Result<(), MitmError> {
        // REFUSE TO START IF UID RESOLUTION FAILED. Passing uid=0 down to
        // install_redirect would install `-m owner --uid-owner 0 -j RETURN`,
        // which is a root-bypass for mitmproxy. This check is belt-and-suspenders
        // with the startup resolve (see netguard_core::config::resolve_system_user
        // which already rejects UID 0); the unwrap_or(0) fallback in main.rs
        // could otherwise feed a zero here silently if getpwnam failed.
        if self.bridge_cfg.uid == 0 {
            return Err(MitmError::NotConfigured(format!(
                "mitmproxy uid_user '{}' did not resolve to a valid non-root UID at startup",
                self.bridge_cfg.uid_user
            )));
        }
        let mut state = self.state.lock().await;
        if state.enabled {
            return Ok(());
        }
        let (handle, port) = spawn_mitm_bridge(self.bridge_cfg.clone(), self.flow_cache.clone())
            .await
            .map_err(|e| MitmError::Spawn(e.to_string()))?;
        // Give mitmdump ~800ms to bind its listener before REDIRECT starts
        // steering traffic at it, otherwise early connections get refused.
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        // Use the actual bound port, not the configured one: the port-probe
        // fallback in spawn_mitm_bridge may have picked a different port if
        // the configured one was busy, and the REDIRECT rule has to point
        // at the real listener or interception silently breaks.
        if let Err(e) = install_redirect(self.bridge_cfg.uid, port) {
            tracing::error!("failed to install REDIRECT rules: {e}");
            // Tear the half-started bridge down cleanly: SIGKILL mitmdump,
            // await reap, remove socket, abort tasks. Otherwise the port
            // stays bound and the next enable() races on `bind()`.
            handle.shutdown().await;
            return Err(MitmError::Iptables(e));
        }
        state.bridge = Some(handle);
        state.bound_listen_port = Some(port);
        state.enabled = true;
        tracing::info!("mitmproxy enabled");
        Ok(())
    }

    /// Remove REDIRECT rules and shut the bridge down gracefully. Waits for
    /// mitmdump to actually exit + releases the listen port + removes the
    /// unix socket before returning, so a subsequent `enable()` gets a clean
    /// slate (avoids `Address already in use` on rapid toggle off → on).
    /// Idempotent.
    pub async fn disable(&self) -> Result<(), MitmError> {
        // Take the handle out of shared state first so we don't hold the
        // state mutex across the (potentially multi-second) shutdown wait.
        let bridge = {
            let mut state = self.state.lock().await;
            if !state.enabled {
                return Ok(());
            }
            state.enabled = false;
            state.bridge.take()
        };
        if let Err(e) = remove_redirect() {
            tracing::warn!("REDIRECT cleanup reported an error: {e}");
        }
        if let Some(handle) = bridge {
            handle.shutdown().await;
        }
        // Clear the bound port only after the bridge has actually been torn
        // down, so a concurrent `bound_listen_port()` reader won't observe a
        // stale port pointing at a mitmdump that's already dead.
        self.state.lock().await.bound_listen_port = None;
        tracing::info!("mitmproxy disabled");
        Ok(())
    }

    /// Port mitmdump is actually listening on, or `None` when disabled.
    /// Differs from `self.bridge_cfg.listen_port` when the port-probe
    /// fallback selected a different port at startup.
    pub async fn bound_listen_port(&self) -> Option<u16> {
        self.state.lock().await.bound_listen_port
    }
}

fn install_redirect(uid: u32, port: u16) -> Result<(), String> {
    let port_str = port.to_string();
    let uid_str = uid.to_string();
    let _ = run_ipt(&["-t", "nat", "-N", "NETGUARD_REDIR"]);
    let _ = run_ipt(&["-t", "nat", "-F", "NETGUARD_REDIR"]);
    run_ipt(&[
        "-t", "nat", "-A", "NETGUARD_REDIR",
        "-m", "owner", "--uid-owner", &uid_str,
        "-j", "RETURN",
    ])?;
    run_ipt(&[
        "-t", "nat", "-A", "NETGUARD_REDIR",
        "-p", "tcp", "--dport", "80",
        "-j", "REDIRECT", "--to-ports", &port_str,
    ])?;
    run_ipt(&[
        "-t", "nat", "-A", "NETGUARD_REDIR",
        "-p", "tcp", "--dport", "443",
        "-j", "REDIRECT", "--to-ports", &port_str,
    ])?;
    let _ = run_ipt(&["-t", "nat", "-D", "OUTPUT", "-j", "NETGUARD_REDIR"]);
    run_ipt(&["-t", "nat", "-I", "OUTPUT", "1", "-j", "NETGUARD_REDIR"])?;
    Ok(())
}

fn remove_redirect() -> Result<(), String> {
    let _ = run_ipt(&["-t", "nat", "-D", "OUTPUT", "-j", "NETGUARD_REDIR"]);
    let _ = run_ipt(&["-t", "nat", "-F", "NETGUARD_REDIR"]);
    let _ = run_ipt(&["-t", "nat", "-X", "NETGUARD_REDIR"]);
    Ok(())
}

fn run_ipt(args: &[&str]) -> Result<(), String> {
    let output = Command::new("iptables")
        .args(args)
        .output()
        .map_err(|e| format!("failed to exec iptables: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("iptables {} failed: {}", args.join(" "), stderr.trim()));
    }
    Ok(())
}
