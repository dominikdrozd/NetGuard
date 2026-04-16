use crate::dns::DnsCache;
use crate::queue::PacketEvent;
use netguard_core::connection_log::ConnectionLog;
use netguard_core::models::*;
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
) {
    while let Some(event) = event_rx.recv().await {
        let mut conn = event.connection;

        // Resolve hostname, but skip DNS traffic (port 53) to avoid feedback loop:
        // reverse DNS lookup -> DNS query -> intercepted -> reverse DNS lookup -> ...
        if conn.hostname.is_none() && conn.dst_port != 53 {
            let ip = conn.dst_ip;
            let cache = dns_cache.clone();

            // Check DNS cache first (might have been populated by another packet)
            if let Some(domain) = cache.lookup(&ip) {
                conn.hostname = Some(domain);
            } else {
                // Async reverse DNS lookup (non-blocking)
                if let Some(hostname) = reverse_dns_lookup(ip).await {
                    cache.insert(ip, hostname.clone());
                    conn.hostname = Some(hostname);
                }
            }
        }

        // Broadcast to WebSocket clients
        let _ = event_tx.send(WsEvent::NewConnection(conn.clone()));

        // Log
        connection_log.push(conn).await;
    }

    tracing::info!("Event channel closed, event processor shutting down");
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
