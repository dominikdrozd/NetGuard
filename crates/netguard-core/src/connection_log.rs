use crate::models::*;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Shared connection log with bounded capacity.
/// Uses AtomicU64 for counters to avoid lock ordering issues.
pub struct ConnectionLog {
    entries: RwLock<VecDeque<Connection>>,
    max_entries: usize,
    total_allowed: AtomicU64,
    total_denied: AtomicU64,
}

impl ConnectionLog {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(VecDeque::with_capacity(max_entries)),
            max_entries,
            total_allowed: AtomicU64::new(0),
            total_denied: AtomicU64::new(0),
        }
    }

    pub async fn push(&self, conn: Connection) {
        match conn.verdict {
            Verdict::Allow => { self.total_allowed.fetch_add(1, Ordering::Relaxed); }
            Verdict::Deny => { self.total_denied.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }

        let mut entries = self.entries.write().await;
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
