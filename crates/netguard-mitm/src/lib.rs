use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;
use tokio::sync::RwLock;

pub const ADDON_PY: &str = include_str!("addon.py");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitmFlow {
    pub flow_id: String,
    pub client_ip: String,
    pub client_port: u16,
    pub server_ip: String,
    pub server_port: u16,
    pub method: String,
    pub url: String,
    pub request_headers: String,
    pub request_body: String,
    pub status_code: u16,
    pub response_headers: String,
    pub response_body: String,
    #[serde(default)]
    pub started_at: f64,
}

/// Key used to correlate a mitmproxy flow with an NFQUEUE packet event.
/// The full 4-tuple (src_ip, src_port, dst_ip, dst_port) is used because
/// client ephemeral ports can be reused across the cache TTL window, and
/// because a looser key (src_ip, src_port) would allow a malicious or
/// confused flow emitter to inject decrypted content that looks like it
/// belongs to an unrelated connection.
pub type FlowKey = (IpAddr, u16, IpAddr, u16);

pub struct MitmFlowCache {
    inner: RwLock<HashMap<FlowKey, CachedFlow>>,
    ttl_secs: u64,
}

struct CachedFlow {
    flow: MitmFlow,
    inserted_at: Instant,
}

impl MitmFlowCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            ttl_secs,
        }
    }

    pub async fn insert(&self, key: FlowKey, flow: MitmFlow) {
        let mut guard = self.inner.write().await;
        guard.insert(
            key,
            CachedFlow {
                flow,
                inserted_at: Instant::now(),
            },
        );
    }

    pub async fn take(&self, key: &FlowKey) -> Option<MitmFlow> {
        let mut guard = self.inner.write().await;
        guard.remove(key).map(|c| c.flow)
    }

    pub async fn get(&self, key: &FlowKey) -> Option<MitmFlow> {
        let guard = self.inner.read().await;
        guard.get(key).map(|c| c.flow.clone())
    }

    pub async fn evict_expired(&self) {
        let ttl = std::time::Duration::from_secs(self.ttl_secs);
        let mut guard = self.inner.write().await;
        guard.retain(|_, c| c.inserted_at.elapsed() < ttl);
    }
}

#[cfg(unix)]
pub mod bridge;
#[cfg(not(unix))]
mod bridge_stub;

#[cfg(unix)]
pub use bridge::{spawn_mitm_bridge, MitmBridgeConfig, MitmBridgeHandle};
#[cfg(not(unix))]
pub use bridge_stub::{spawn_mitm_bridge, MitmBridgeConfig, MitmBridgeHandle};

pub mod controller;
pub use controller::{MitmControllerStatus, MitmError, MitmProxyController};
