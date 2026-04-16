use crate::models::*;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Shared connection log with bounded capacity.
/// Uses AtomicU64 for counters to avoid lock ordering issues.
pub struct ConnectionLog {
    entries: RwLock<VecDeque<Connection>>,
    max_entries: usize,
    total_allowed: AtomicU64,
    total_denied: AtomicU64,
    disk: Option<Mutex<BufWriter<File>>>,
    disk_path: Option<PathBuf>,
    persist_bodies: bool,
}

/// JSONL record format written to the on-disk connection log.
/// Each line is a discrete event; readers merge by connection id.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum DiskRecord<'a> {
    Conn { data: &'a Connection },
    Enrich { id: Uuid, fields: &'a EnrichmentDelta },
}

impl ConnectionLog {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(VecDeque::with_capacity(max_entries)),
            max_entries,
            total_allowed: AtomicU64::new(0),
            total_denied: AtomicU64::new(0),
            disk: None,
            disk_path: None,
            persist_bodies: true,
        }
    }

    /// Enable append-only JSONL persistence to `path`. The parent directory is
    /// created if missing; the file is opened in append mode with mode 0600 so
    /// decrypted bodies are only readable by root.
    ///
    /// If `persist_bodies` is false, decrypted body fields are stripped before
    /// writing (headers/status still persist so forensic correlation works).
    pub fn with_disk_log(
        mut self,
        path: impl AsRef<Path>,
        persist_bodies: bool,
    ) -> std::io::Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        // Open with mode 0600 at creation time (not via a subsequent chmod)
        // to close the TOCTOU window where the default-umask file briefly has
        // world-readable permissions and can be opened by a concurrent
        // unprivileged process. On append to an existing file the mode
        // argument is ignored; we re-assert chmod 600 below as a safety net.
        #[cfg(target_os = "linux")]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)?
        };
        #[cfg(not(target_os = "linux"))]
        let file = OpenOptions::new().create(true).append(true).open(path)?;

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        self.disk = Some(Mutex::new(BufWriter::new(file)));
        self.disk_path = Some(path.to_path_buf());
        self.persist_bodies = persist_bodies;
        Ok(self)
    }

    fn write_disk(&self, record: DiskRecord<'_>) {
        let Some(writer) = self.disk.as_ref() else { return };
        let mut line = match serde_json::to_string(&record) {
            Ok(s) => s,
            Err(_) => return,
        };
        line.push('\n');
        let mut guard = match writer.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _ = guard.write_all(line.as_bytes());
        let _ = guard.flush();
    }

    pub async fn push(&self, conn: Connection) {
        match conn.verdict {
            Verdict::Allow => { self.total_allowed.fetch_add(1, Ordering::Relaxed); }
            Verdict::Deny => { self.total_denied.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }

        let mut entries = self.entries.write().await;
        // Disk write is now emitted UNDER the entries lock so `enrich` can't
        // land its disk record before the corresponding `push`. A log replay
        // reader is guaranteed to see Conn before Enrich for the same id.
        if self.disk.is_some() {
            let sanitized;
            let to_write: &Connection = if self.persist_bodies {
                &conn
            } else {
                sanitized = strip_bodies(&conn);
                &sanitized
            };
            self.write_disk(DiskRecord::Conn { data: to_write });
        }
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back(conn);
    }

    pub async fn recent(&self, limit: usize, offset: usize) -> Vec<Connection> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .rev()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    pub async fn get(&self, id: Uuid) -> Option<Connection> {
        let entries = self.entries.read().await;
        entries.iter().find(|c| c.id == id).cloned()
    }

    /// Merge decrypted mitmproxy flow data into an existing connection record.
    /// Used for late-merge after the flow completes. Both disk and in-memory
    /// updates happen under the same entries write-lock so enrichment records
    /// can never be written to disk before the corresponding conn record, and
    /// an enrichment for an unknown id is dropped (no orphan on-disk events).
    pub async fn enrich(&self, id: Uuid, delta: EnrichmentDelta) {
        let mut entries = self.entries.write().await;
        let Some(conn) = entries.iter_mut().find(|c| c.id == id) else {
            // In-memory entry already evicted; drop the disk write too to
            // avoid orphan Enrich records that log-replay readers can't merge.
            return;
        };

        if self.disk.is_some() {
            let disk_delta = if self.persist_bodies {
                delta.clone()
            } else {
                EnrichmentDelta {
                    request_url: delta.request_url.clone(),
                    http_method: delta.http_method.clone(),
                    hostname: delta.hostname.clone(),
                    payload_hex: delta.payload_hex.clone(),
                    decrypted_request_headers: delta.decrypted_request_headers.clone(),
                    decrypted_request_body: None,
                    decrypted_response_status: delta.decrypted_response_status,
                    decrypted_response_headers: delta.decrypted_response_headers.clone(),
                    decrypted_response_body: None,
                }
            };
            self.write_disk(DiskRecord::Enrich { id, fields: &disk_delta });
        }

        // Overwrite the NFQUEUE-derived hostname/URL/method if mitmproxy
        // provided decrypted equivalents — the decrypted view is always more
        // accurate (full path for HTTPS, real method/host even for h2).
        if delta.request_url.is_some() {
            conn.request_url = delta.request_url;
        }
        if delta.http_method.is_some() {
            conn.http_method = delta.http_method;
        }
        if let Some(host) = delta.hostname {
            conn.hostname = Some(host);
        }
        if delta.payload_hex.is_some() {
            conn.payload_hex = delta.payload_hex;
        }
        if delta.decrypted_request_headers.is_some() {
            conn.decrypted_request_headers = delta.decrypted_request_headers;
        }
        if delta.decrypted_request_body.is_some() {
            conn.decrypted_request_body = delta.decrypted_request_body;
        }
        if delta.decrypted_response_status.is_some() {
            conn.decrypted_response_status = delta.decrypted_response_status;
        }
        if delta.decrypted_response_headers.is_some() {
            conn.decrypted_response_headers = delta.decrypted_response_headers;
        }
        if delta.decrypted_response_body.is_some() {
            conn.decrypted_response_body = delta.decrypted_response_body;
        }
    }

    #[allow(dead_code)] // Public API, used by tests and external consumers
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    pub async fn stats(&self) -> DashboardStats {
        let entries = self.entries.read().await;
        // Read atomics after acquiring entries lock for a consistent-enough snapshot
        let total_allowed = self.total_allowed.load(Ordering::Relaxed);
        let total_denied = self.total_denied.load(Ordering::Relaxed);

        // Calculate connections per second (count entries in last 5 seconds)
        let now = chrono::Utc::now();
        let five_sec_ago = now - chrono::Duration::seconds(5);
        let recent_count = entries
            .iter()
            .rev()
            .take_while(|c| c.timestamp > five_sec_ago)
            .count();
        let connections_per_second = recent_count as f64 / 5.0;

        // Count top apps
        let mut app_counts: HashMap<String, u64> = HashMap::new();
        for conn in entries.iter() {
            let app = conn
                .process
                .as_ref()
                .map(|p| p.exe_path.clone())
                .unwrap_or_else(|| "unknown".to_string());
            *app_counts.entry(app).or_default() += 1;
        }
        let mut top_apps: Vec<(String, u64)> = app_counts.into_iter().collect();
        top_apps.sort_by(|a, b| b.1.cmp(&a.1));
        top_apps.truncate(10);

        DashboardStats {
            active_connections: entries.len() as u64,
            total_allowed,
            total_denied,
            connections_per_second,
            top_apps,
        }
    }
}

fn strip_bodies(conn: &Connection) -> Connection {
    let mut c = conn.clone();
    c.decrypted_request_body = None;
    c.decrypted_response_body = None;
    c
}
