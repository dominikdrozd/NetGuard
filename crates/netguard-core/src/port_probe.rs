//! Bind a TCP listener starting at `start_port` and incrementing up to
//! `start_port + max_attempts - 1` if the starting port is busy.

use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpListener;

/// Try to bind a TCP listener, starting at `start_port`. If `AddrInUse`,
/// increment the port and retry up to `max_attempts - 1` additional times.
/// Returns `(listener, bound_port)`. Any error other than `AddrInUse`
/// aborts immediately.
pub async fn try_bind_from(
    ip: IpAddr,
    start_port: u16,
    max_attempts: u16,
) -> io::Result<(TcpListener, u16)> {
    let mut last_err: Option<io::Error> = None;
    for offset in 0..max_attempts {
        let Some(port) = start_port.checked_add(offset) else { break };
        let bind_addr = SocketAddr::new(ip, port);
        match TcpListener::bind(bind_addr).await {
            Ok(l) => return Ok((l, port)),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    let last_port = start_port.saturating_add(max_attempts.saturating_sub(1));
    let msg = format!(
        "no free port in {start_port}..={last_port} (last error: {})",
        last_err
            .as_ref()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "none attempted".into())
    );
    Err(io::Error::new(
        last_err.map(|e| e.kind()).unwrap_or(io::ErrorKind::AddrInUse),
        msg,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    #[tokio::test]
    async fn returns_start_port_when_free() {
        // Bind to port 0 to get an OS-assigned port — guaranteed free,
        // then release and ask try_bind_from to claim it.
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let (_listener, bound) = try_bind_from(LOCALHOST, port, 5).await.unwrap();
        assert_eq!(bound, port);
    }

    #[tokio::test]
    async fn falls_back_when_start_port_taken() {
        // Hold port N, ask helper to start at N with 5 attempts — expect N+1..N+4.
        let hold = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = hold.local_addr().unwrap().port();

        let (_listener, bound) = try_bind_from(LOCALHOST, port, 5).await.unwrap();
        assert!(bound >= port + 1 && bound <= port + 4,
            "expected fallback in range, got {bound}");
    }

    #[tokio::test]
    async fn errors_when_no_free_port_in_range() {
        // Occupy 3 consecutive ports, ask helper with max_attempts=3 → error.
        let a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let start = a.local_addr().unwrap().port();
        // Attempt to grab start+1 and start+2. If either is taken by another
        // process on the test host, skip — this is a best-effort test.
        let Ok(_b) = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", start + 1)).await else {
            return;
        };
        let Ok(_c) = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", start + 2)).await else {
            return;
        };

        let result = try_bind_from(LOCALHOST, start, 3).await;
        assert!(result.is_err());
    }
}
