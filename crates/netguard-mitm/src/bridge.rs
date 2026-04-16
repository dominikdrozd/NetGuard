use crate::{MitmFlow, MitmFlowCache, ADDON_PY};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub struct MitmBridgeConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub socket_path: PathBuf,
    pub confdir: PathBuf,
    pub uid_user: String,
    /// Numeric UID that `uid_user` resolved to at startup. iptables owner-match
    /// rules MUST use this numeric value rather than the name so they can't be
    /// silently redirected by /etc/passwd changes. See
    /// `netguard_core::config::resolve_system_user`.
    pub uid: u32,
    pub gid: u32,
    pub max_body_size_bytes: usize,
    pub addon_path: PathBuf,
    /// When true, flow records for non-HTTP ports are rejected. Keeps the
    /// addon from being tricked into bloating the cache for unrelated traffic.
    pub strict_ports: bool,
}

pub struct MitmBridgeHandle {
    pub cache: Arc<MitmFlowCache>,
    pub child: Child,
    pub listener_task: JoinHandle<()>,
    pub evictor_task: JoinHandle<()>,
    pub socket_path: PathBuf,
}

impl MitmBridgeHandle {
    /// Graceful async shutdown that:
    ///   1. Aborts the listener + evictor tokio tasks (they hold file
    ///      descriptors for the unix socket; just dropping their JoinHandles
    ///      would leak the tasks).
    ///   2. Sends SIGKILL to mitmdump and awaits its exit so the kernel
    ///      fully releases `listen_port` before the next `enable()` tries
    ///      to bind it (race that made a rapid off->on toggle crash with
    ///      "Address already in use").
    ///   3. Removes the unix socket file so the next `bind()` starts from a
    ///      clean slate.
    pub async fn shutdown(mut self) {
        self.listener_task.abort();
        self.evictor_task.abort();
        let _ = self.child.start_kill();
        // Bounded wait: mitmdump normally dies instantly on SIGKILL, but
        // don't hang forever if the kernel is slow to reap.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            self.child.wait(),
        )
        .await;
        let _ = tokio::fs::remove_file(&self.socket_path).await;
    }
}

/// Start the mitmdump child process and the Unix-socket listener that receives
/// flow records from the embedded Python addon. Returns a handle owning both
/// so the caller can gracefully shut them down.
///
/// The flow cache is provided by the caller so a single long-lived cache can
/// survive across runtime enable/disable toggles (resolver code keeps the
/// cache reference and doesn't need to re-acquire it on each toggle).
pub async fn spawn_mitm_bridge(
    cfg: MitmBridgeConfig,
    cache: Arc<MitmFlowCache>,
) -> std::io::Result<(MitmBridgeHandle, u16)> {

    // Find a free port starting at cfg.listen_port. Drop the probe listener
    // immediately — mitmdump will rebind it moments later. Racy in principle,
    // but the +20 window + localhost-only binding makes collisions rare.
    let bound_port = {
        let ip: std::net::IpAddr = cfg.listen_addr.parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid mitm listen_addr {:?}: {e}", cfg.listen_addr),
            )
        })?;
        let (probe, p) = netguard_core::port_probe::try_bind_from(ip, cfg.listen_port, 20).await?;
        drop(probe);
        p
    };
    if bound_port != cfg.listen_port {
        tracing::warn!(
            "configured mitm port {} was busy; using {} instead",
            cfg.listen_port,
            bound_port,
        );
    }

    // Write the embedded addon script to disk (re-written every start so upgrades pick up changes)
    if let Some(parent) = cfg.addon_path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    tokio::fs::write(&cfg.addon_path, ADDON_PY).await?;

    // Ensure socket directory exists and nuke any stale socket
    if let Some(parent) = cfg.socket_path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    let _ = tokio::fs::remove_file(&cfg.socket_path).await;

    let listener = UnixListener::bind(&cfg.socket_path)?;
    // Lock the socket to root:<mitm_gid> with mode 0660. Only the dedicated
    // mitm user (and root) can connect, blocking local unprivileged users
    // from injecting forged flow records.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg.socket_path, std::fs::Permissions::from_mode(0o660))?;
        chown_to(&cfg.socket_path, 0, cfg.gid)?;
    }

    // Launch mitmdump as the dedicated user. We use `runuser -u` instead of
    // `sudo` so the invocation execs in place and the direct child of this
    // daemon IS mitmdump -- that way tokio's `kill_on_drop(true)` actually
    // terminates mitmdump on daemon crash/shutdown. We also install
    // PR_SET_PDEATHSIG via pre_exec so that even in the narrow window before
    // kill_on_drop fires, if the daemon dies, the kernel delivers SIGTERM to
    // mitmdump and it exits on its own.
    let addon_arg = cfg.addon_path.to_string_lossy().to_string();
    let confdir_arg = format!("confdir={}", cfg.confdir.display());
    let stream_arg = format!("stream_large_bodies={}", cfg.max_body_size_bytes);
    let sock_env = cfg.socket_path.to_string_lossy().to_string();
    let body_env = cfg.max_body_size_bytes.to_string();

    let mut cmd = Command::new("runuser");
    cmd.arg("-u")
        .arg(&cfg.uid_user)
        .arg("--")
        .arg("mitmdump")
        .arg("--mode")
        .arg("transparent")
        .arg("--listen-host")
        .arg(&cfg.listen_addr)
        .arg("--listen-port")
        .arg(bound_port.to_string())
        .arg("-s")
        .arg(&addon_arg)
        .arg("--set")
        .arg(&confdir_arg)
        .arg("--set")
        .arg(&stream_arg)
        // Only forward the two vars the addon actually reads; do NOT leak
        // the whole daemon environment into a reduced-privilege subprocess.
        .env_clear()
        .env("NETGUARD_SOCK", &sock_env)
        .env("NETGUARD_MAX_BODY", &body_env)
        .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", cfg.confdir.as_os_str())
        // Capture both streams so spawn/runtime errors from mitmdump or
        // runuser surface in daemon logs. Silencing them (as the initial
        // implementation did) makes misconfiguration nearly undiagnosable.
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    #[cfg(target_os = "linux")]
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            // PR_SET_PDEATHSIG = 1; SIGTERM = 15
            let rc = libc::prctl(1, 15, 0, 0, 0);
            if rc == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    tracing::info!(
        "spawning mitmdump: runuser -u {} -- mitmdump --mode transparent --listen {}:{}",
        cfg.uid_user,
        cfg.listen_addr,
        bound_port
    );

    let mut child = cmd.spawn().map_err(|e| {
        tracing::error!("failed to spawn mitmdump: {e} (is mitmproxy installed and runuser available?)");
        e
    })?;

    // Forward child stdout/stderr into the daemon's tracing. Without this,
    // mitmdump startup failures (missing binary, addon import errors,
    // iptables listener conflicts) disappear silently and the operator
    // just sees HTTPS stop working.
    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(forward_child_stream(stdout, false));
    }
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(forward_child_stream(stderr, true));
    }

    let listener_cache = cache.clone();
    let strict = cfg.strict_ports;
    let listener_task = tokio::spawn(async move {
        accept_loop(listener, listener_cache, strict).await;
    });

    let evictor_cache = cache.clone();
    let evictor_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            evictor_cache.evict_expired().await;
        }
    });

    Ok((
        MitmBridgeHandle {
            cache,
            child,
            listener_task,
            evictor_task,
            socket_path: cfg.socket_path.clone(),
        },
        bound_port,
    ))
}

/// Forward each line from a child stdout/stderr into the daemon's tracing.
/// `is_err=true` emits at warn level; false at debug. The stream is drained
/// until EOF (child exit) then the task finishes.
async fn forward_child_stream<R: tokio::io::AsyncRead + Unpin>(stream: R, is_err: bool) {
    let mut reader = BufReader::new(stream);
    let mut buf = String::new();
    loop {
        buf.clear();
        match reader.read_line(&mut buf).await {
            Ok(0) => return,
            Ok(_) => {
                let line = buf.trim_end();
                if line.is_empty() {
                    continue;
                }
                if is_err {
                    tracing::warn!(target: "mitmproxy", "{line}");
                } else {
                    tracing::debug!(target: "mitmproxy", "{line}");
                }
            }
            Err(_) => return,
        }
    }
}

#[cfg(target_os = "linux")]
fn chown_to(path: &std::path::Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has NUL"))?;
    let rc = unsafe { libc::chown(c.as_ptr(), uid, gid) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

async fn accept_loop(listener: UnixListener, cache: Arc<MitmFlowCache>, strict_ports: bool) {
    // Cap per-line input at 4 MiB. mitmproxy's addon already caps body size to
    // `NETGUARD_MAX_BODY` (default 1 MiB), but we defend against anything that
    // manages to bypass the chmod 0660 gate.
    const MAX_LINE: usize = 4 * 1024 * 1024;
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let cache = cache.clone();
                tokio::spawn(async move {
                    let mut reader = BufReader::with_capacity(64 * 1024, stream);
                    loop {
                        let mut buf = Vec::new();
                        let n = match reader.read_until(b'\n', &mut buf).await {
                            Ok(n) => n,
                            Err(e) => {
                                tracing::debug!("mitm socket read error: {e}");
                                break;
                            }
                        };
                        if n == 0 {
                            break;
                        }
                        if buf.len() > MAX_LINE {
                            tracing::warn!(
                                "dropped oversized mitm flow line: {} bytes",
                                buf.len()
                            );
                            continue;
                        }
                        // Trim the trailing '\n'
                        if buf.last() == Some(&b'\n') {
                            buf.pop();
                        }
                        if let Ok(line) = std::str::from_utf8(&buf) {
                            handle_line(line, &cache, strict_ports).await;
                        }
                    }
                });
            }
            Err(e) => {
                tracing::warn!("mitm listener accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    }
}

async fn handle_line(line: &str, cache: &MitmFlowCache, strict_ports: bool) {
    let flow: MitmFlow = match serde_json::from_str(line) {
        Ok(f) => f,
        Err(e) => {
            tracing::debug!("mitm flow parse error: {e}");
            return;
        }
    };
    let src_ip: IpAddr = match flow.client_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return,
    };
    let dst_ip: IpAddr = match flow.server_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return,
    };
    if strict_ports && !matches!(flow.server_port, 80 | 443) {
        // Reject flows that claim to be to non-HTTP ports to stop the cache
        // filling with junk if a misconfigured proxy ever writes to the socket.
        tracing::debug!("rejected mitm flow with server_port={}", flow.server_port);
        return;
    }
    let key = (src_ip, flow.client_port, dst_ip, flow.server_port);
    cache.insert(key, flow).await;
}
