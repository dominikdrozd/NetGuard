use netguard_core::errors::NetGuardError;
use netguard_core::models::{ProcessInfo, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Maps socket inodes to process information.
/// Maintains a background-refreshed cache for fast lookups.
///
/// Uses `std::sync::RwLock` so the cache can be safely accessed from both
/// the NFQUEUE OS thread (blocking) and the tokio async runtime.
///
/// **Note on TOCTOU:** There is an inherent race between reading `/proc/net/tcp`
/// (to find the inode) and looking up the inode in the PID cache. A process could
/// exit between these two reads, or a new process could reuse the socket inode.
/// This is a known limitation of the `/proc`-based approach shared by all Linux
/// application firewalls (OpenSnitch, Portmaster). The 2-second cache refresh
/// minimizes but cannot eliminate this window.
pub struct ProcMapper {
    inode_cache: Arc<RwLock<HashMap<u64, ProcessInfo>>>,
    refresh_interval: Duration,
}

impl ProcMapper {
    pub fn new(refresh_interval_ms: u64) -> Self {
        Self {
            inode_cache: Arc::new(RwLock::new(HashMap::new())),
            refresh_interval: Duration::from_millis(refresh_interval_ms),
        }
    }

    /// Build the inode-to-process cache by scanning /proc/[pid]/fd/.
    pub async fn rebuild_cache(&self) -> Result<(), NetGuardError> {
        let map = tokio::task::spawn_blocking(build_inode_to_process_map)
            .await
            .map_err(|e| NetGuardError::ProcessLookup(format!("Task join error: {e}")))?;

        let mut cache = self.inode_cache.write().unwrap_or_else(|e| e.into_inner());
        *cache = map;
        Ok(())
    }

    /// Synchronous process lookup for the NFQUEUE thread.
    /// Reads /proc directly -- does NOT use async runtime.
    pub fn lookup_sync(
        &self,
        protocol: Protocol,
        local_ip: IpAddr,
        local_port: u16,
    ) -> Option<ProcessInfo> {
        let inode = find_inode_for_socket(protocol, local_ip, local_port)?;

        // Try the cache
        let cache = self.inode_cache.read().unwrap_or_else(|e| e.into_inner());
        if let Some(info) = cache.get(&inode) {
            return Some(info.clone());
        }
        drop(cache);

        // Cache miss -- do a targeted scan
        let map = build_inode_to_process_map();
        let result = map.get(&inode).cloned();

        // Update cache with the new scan
        let mut cache = self.inode_cache.write().unwrap_or_else(|e| e.into_inner());
        *cache = map;

        result
    }

    /// Async process lookup for non-critical-path code.
    pub async fn lookup(
        &self,
        protocol: Protocol,
        local_ip: IpAddr,
        local_port: u16,
    ) -> Option<ProcessInfo> {
        let inode = tokio::task::spawn_blocking(move || {
            find_inode_for_socket(protocol, local_ip, local_port)
        })
        .await
        .ok()??;

        let cache = self.inode_cache.read().unwrap_or_else(|e| e.into_inner());
        if let Some(info) = cache.get(&inode) {
            return Some(info.clone());
        }
        drop(cache);

        let _ = self.rebuild_cache().await;
        let cache = self.inode_cache.read().unwrap_or_else(|e| e.into_inner());
        cache.get(&inode).cloned()
    }

    /// Run the background cache refresh loop.
    pub async fn run_cache_refresh_loop(&self) {
        loop {
            if let Err(e) = self.rebuild_cache().await {
                tracing::warn!("Failed to rebuild proc cache: {e}");
            }
            tokio::time::sleep(self.refresh_interval).await;
        }
    }
}

fn find_inode_for_socket(protocol: Protocol, local_ip: IpAddr, local_port: u16) -> Option<u64> {
    match protocol {
        Protocol::Tcp => find_tcp_inode(local_ip, local_port),
        Protocol::Udp => find_udp_inode(local_ip, local_port),
        _ => None,
    }
}

fn find_tcp_inode(local_ip: IpAddr, local_port: u16) -> Option<u64> {
    let entries = match local_ip {
        IpAddr::V4(_) => procfs::net::tcp().ok()?,
        IpAddr::V6(_) => procfs::net::tcp6().ok()?,
    };
    for entry in entries {
        if entry.local_address.port() == local_port
            && (entry.local_address.ip() == local_ip
                || entry.local_address.ip().is_unspecified())
        {
            return Some(entry.inode);
        }
    }
    None
}

fn find_udp_inode(local_ip: IpAddr, local_port: u16) -> Option<u64> {
    let entries = match local_ip {
        IpAddr::V4(_) => procfs::net::udp().ok()?,
        IpAddr::V6(_) => procfs::net::udp6().ok()?,
    };
    for entry in entries {
        if entry.local_address.port() == local_port
            && (entry.local_address.ip() == local_ip
                || entry.local_address.ip().is_unspecified())
        {
            return Some(entry.inode);
        }
    }
    None
}

fn build_inode_to_process_map() -> HashMap<u64, ProcessInfo> {
    let mut map = HashMap::new();
    let processes = match procfs::process::all_processes() {
        Ok(p) => p,
        Err(_) => return map,
    };

    for proc_result in processes {
        let process = match proc_result {
            Ok(p) => p,
            Err(_) => continue,
        };

        let pid = process.pid() as u32;
        let fds = match process.fd() {
            Ok(f) => f,
            Err(_) => continue,
        };

        let exe_path = process
            .exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let cmdline = process
            .cmdline()
            .map(|c| c.join(" "))
            .unwrap_or_default();
        let uid = process.status().map(|s| s.ruid).unwrap_or(0);
        let username = resolve_username(uid);

        for fd_result in fds {
            let fd = match fd_result {
                Ok(f) => f,
                Err(_) => continue,
            };

            if let procfs::process::FDTarget::Socket(inode) = fd.target {
                map.insert(
                    inode,
                    ProcessInfo {
                        pid,
                        exe_path: exe_path.clone(),
                        cmdline: cmdline.clone(),
                        uid,
                        username: username.clone(),
                    },
                );
            }
        }
    }

    map
}

/// Resolve a UID to a username by reading /etc/passwd.
fn resolve_username(uid: u32) -> String {
    let passwd = match std::fs::read_to_string("/etc/passwd") {
        Ok(s) => s,
        Err(_) => return uid.to_string(),
    };
    for line in passwd.lines() {
        let fields: Vec<&str> = line.splitn(4, ':').collect();
        if fields.len() >= 3 {
            if let Ok(parsed_uid) = fields[2].parse::<u32>() {
                if parsed_uid == uid {
                    return fields[0].to_string();
                }
            }
        }
    }
    uid.to_string()
}
