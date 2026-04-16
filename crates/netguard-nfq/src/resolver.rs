use crate::dns::DnsCache;
use crate::queue::PacketEvent;
use netguard_core::connection_log::ConnectionLog;
use netguard_core::models::*;
use netguard_mitm::MitmFlowCache;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Run the async event processor that logs connections and broadcasts to the UI.
/// Verdicts are already decided by the NFQUEUE thread -- this is logging/display only.
/// Also performs async reverse DNS lookups for hostname resolution.
pub async fn run_event_processor(
    mut event_rx: tokio::sync::mpsc::Receiver<PacketEvent>,
    event_tx: broadcast::Sender<WsEvent>,
    connection_log: Arc<ConnectionLog>,
    dns_cache: Arc<DnsCache>,
    mitm_cache: Option<Arc<MitmFlowCache>>,
    mitm_idle_timeout_secs: u64,
) {
    while let Some(event) = event_rx.recv().await {
        let mut conn = event.connection;

        // Resolve hostname from DNS cache only (no active lookups to avoid feedback loops)
        if conn.hostname.is_none() {
            if let Some(domain) = dns_cache.lookup(&conn.dst_ip) {
                conn.hostname = Some(domain);
            }
        }

        // Broadcast to WebSocket clients
        let _ = event_tx.send(WsEvent::NewConnection(conn.clone()));

        // If mitmproxy is enabled and this looks like an HTTP/HTTPS connection,
        // poll the flow cache for a matching decrypted flow and emit an
        // ConnectionEnriched update when it lands. The flow arrives AFTER the
        // NFQUEUE packet event, so this is a deliberate late-merge.
        if let Some(cache) = mitm_cache.as_ref() {
            if is_http_ish(&conn) {
                spawn_enrichment_task(
                    cache.clone(),
                    event_tx.clone(),
                    connection_log.clone(),
                    conn.clone(),
                    mitm_idle_timeout_secs,
                );
            }
        }

        // Log
        connection_log.push(conn).await;
    }

    tracing::info!("Event channel closed, event processor shutting down");
}

fn is_http_ish(conn: &Connection) -> bool {
    matches!(conn.dst_port, 80 | 443 | 8080 | 8443)
}

fn spawn_enrichment_task(
    cache: Arc<MitmFlowCache>,
    event_tx: broadcast::Sender<WsEvent>,
    connection_log: Arc<ConnectionLog>,
    conn: Connection,
    idle_timeout_secs: u64,
) {
    tokio::spawn(async move {
        // Full 4-tuple key — see netguard_mitm::FlowKey docstring for why this
        // is mandatory rather than just (src_ip, src_port).
        let key = (conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port);
        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_secs(idle_timeout_secs.max(1));
        loop {
            if let Some(flow) = cache.take(&key).await {
                // Defensive cross-check: even with a full-tuple key, reject
                // the enrichment if the server IP/port recorded by mitmproxy
                // doesn't match this connection's destination. A mismatch
                // implies cache key collision or a forged flow record.
                let server_ip_ok = flow
                    .server_ip
                    .parse::<IpAddr>()
                    .map(|ip| ip == conn.dst_ip)
                    .unwrap_or(false);
                if !server_ip_ok || flow.server_port != conn.dst_port {
                    tracing::warn!(
                        "dropping mitm flow with mismatched server addr: expected {}:{}, got {}:{}",
                        conn.dst_ip,
                        conn.dst_port,
                        flow.server_ip,
                        flow.server_port
                    );
                    return;
                }
                let delta = EnrichmentDelta {
                    decrypted_request_headers: Some(flow.request_headers),
                    decrypted_request_body: if flow.request_body.is_empty() {
                        None
                    } else {
                        Some(flow.request_body)
                    },
                    decrypted_response_status: Some(flow.status_code),
                    decrypted_response_headers: Some(flow.response_headers),
                    decrypted_response_body: if flow.response_body.is_empty() {
                        None
                    } else {
                        Some(flow.response_body)
                    },
                };
                let _ = event_tx.send(WsEvent::ConnectionEnriched {
                    id: conn.id,
                    fields: delta.clone(),
                });
                connection_log.enrich(conn.id, delta).await;
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    });
}

/// Perform an async reverse DNS lookup using tokio's DNS resolver.
async fn reverse_dns_lookup(ip: IpAddr) -> Option<String> {
    // Use tokio's spawn_blocking to call the system resolver
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        tokio::task::spawn_blocking(move || {
            // Use the system's gethostbyaddr via std's lookup
            use std::net::ToSocketAddrs;
            // Construct a socket addr and try reverse lookup
            let addr = std::net::SocketAddr::new(ip, 0);
            // dns_lookup crate or manual: parse /etc/hosts and use getaddrinfo reverse
            // Simplest: use the `dns-lookup` approach via libc getnameinfo
            reverse_lookup_libc(ip)
        }),
    )
    .await;

    match result {
        Ok(Ok(Some(name))) => Some(name),
        _ => None,
    }
}

/// Call libc getnameinfo for reverse DNS (PTR) lookup.
#[cfg(target_os = "linux")]
fn reverse_lookup_libc(ip: IpAddr) -> Option<String> {
    use std::ffi::CStr;
    use std::mem;

    unsafe {
        let mut host = [0u8; 256];

        match ip {
            IpAddr::V4(v4) => {
                let mut sa: libc::sockaddr_in = mem::zeroed();
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());

                let ret = libc::getnameinfo(
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr() as *mut libc::c_char,
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    0, // NI_NAMEREQD would return error if no name found
                );

                if ret == 0 {
                    let name = CStr::from_ptr(host.as_ptr() as *const libc::c_char)
                        .to_string_lossy()
                        .to_string();
                    // If getnameinfo returns the IP string itself, it means no PTR record
                    if name == ip.to_string() {
                        None
                    } else {
                        Some(name)
                    }
                } else {
                    None
                }
            }
            IpAddr::V6(v6) => {
                let mut sa: libc::sockaddr_in6 = mem::zeroed();
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_addr.s6_addr = v6.octets();

                let ret = libc::getnameinfo(
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr() as *mut libc::c_char,
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    0,
                );

                if ret == 0 {
                    let name = CStr::from_ptr(host.as_ptr() as *const libc::c_char)
                        .to_string_lossy()
                        .to_string();
                    if name == ip.to_string() {
                        None
                    } else {
                        Some(name)
                    }
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn reverse_lookup_libc(_ip: IpAddr) -> Option<String> {
    None
}
