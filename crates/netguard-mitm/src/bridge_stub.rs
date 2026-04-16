//! Non-Unix stub so the crate at least type-checks on Windows for editor
//! support. mitmproxy integration only runs on Linux in production.

use crate::MitmFlowCache;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct MitmBridgeConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub socket_path: PathBuf,
    pub confdir: PathBuf,
    pub uid_user: String,
    pub uid: u32,
    pub gid: u32,
    pub max_body_size_bytes: usize,
    pub addon_path: PathBuf,
    pub strict_ports: bool,
}

pub struct MitmBridgeHandle {
    pub cache: Arc<MitmFlowCache>,
}

impl MitmBridgeHandle {
    pub async fn shutdown(self) {}
}

pub async fn spawn_mitm_bridge(
    _cfg: MitmBridgeConfig,
    _cache: Arc<MitmFlowCache>,
) -> std::io::Result<MitmBridgeHandle> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "mitmproxy bridge is only supported on Unix targets",
    ))
}
