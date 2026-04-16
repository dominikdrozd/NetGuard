use crate::dns::DnsCache;
use crate::packet::parse_ip_packet;
use crate::procmap::ProcMapper;
use crate::http;
use crate::tls;
use chrono::Utc;
use netguard_core::errors::NetGuardError;
use netguard_core::models::*;
use netguard_core::rule_engine::RuleEngine;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Raw packet info sent to the async resolver for logging/prompting.
#[derive(Debug)]
pub struct PacketEvent {
    pub connection: Connection,
}

/// Run the NFQUEUE receive loop on a dedicated OS thread.
/// This is blocking I/O - must NOT run on the tokio runtime.
///
/// Evaluates rules synchronously and issues verdicts inline.
/// Sends connection info to `event_tx` for async logging/UI updates.
pub fn run_nfqueue_loop(
    queue_num: u16,
    rule_engine: Arc<RwLock<RuleEngine>>,
    proc_mapper: Arc<ProcMapper>,
    event_tx: std::sync::mpsc::Sender<PacketEvent>,
    default_verdict: Verdict,
    whitelist: Vec<String>,
    intercept_inbound: bool,
    dns_cache: Arc<DnsCache>,
) -> Result<(), NetGuardError> {
    let mut queue = nfq::Queue::open()
        .map_err(|e| NetGuardError::NfQueue(format!("Failed to open NFQUEUE: {e}")))?;

    queue
        .bind(queue_num)
        .map_err(|e| NetGuardError::NfQueue(format!("Failed to bind queue {queue_num}: {e}")))?;

    tracing::info!("NFQUEUE bound to queue {queue_num}");

    let my_pid = std::process::id();
    let mut consecutive_errors: u32 = 0;

    loop {
        match queue.recv() {
            Ok(mut msg) => {
                consecutive_errors = 0;
                let payload = msg.get_payload().to_vec();

                // Parse packet
                let parsed = match parse_ip_packet(&payload) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::debug!("Failed to parse packet: {e}");
                        // Can't evaluate, accept to avoid blocking unknown traffic
                        msg.set_verdict(nfq::Verdict::Accept);
                        if let Err(e) = queue.verdict(msg) {
                            tracing::error!("Failed to set verdict: {e}");
                        }
                        continue;
                    }
                };

                // Look up process (synchronous)
                let process = proc_mapper.lookup_sync(
                    parsed.protocol,
                    parsed.src_ip,
                    parsed.src_port,
                );

                // Skip our own traffic (prevents feedback loops)
                if process.as_ref().map_or(false, |p| p.pid == my_pid) {
                    msg.set_verdict(nfq::Verdict::Accept);
                    if let Err(e) = queue.verdict(msg) {
                        tracing::error!("Failed to set verdict: {e}");
                    }
                    continue;
                }

                // Skip DNS traffic (port 53) -- always allow, don't log
                // Prevents feedback loop from reverse DNS lookups
                if parsed.dst_port == 53 || parsed.src_port == 53 {
                    msg.set_verdict(nfq::Verdict::Accept);
                    if let Err(e) = queue.verdict(msg) {
                        tracing::error!("Failed to set verdict: {e}");
                    }
                    // Still feed to DNS sniffer for domain resolution
                    if parsed.src_port == 53 {
                        dns_cache.parse_dns_response(&parsed.transport_payload);
                    }
                    continue;
                }

                // Check whitelist
                let is_whitelisted = process.as_ref().map_or(false, |p| {
                    whitelist.iter().any(|w| {
                        netguard_core::rule_engine::match_app_path(w, &p.exe_path)
                    })
                });

                if is_whitelisted {
                    msg.set_verdict(nfq::Verdict::Accept);
                    if let Err(e) = queue.verdict(msg) {
                        tracing::error!("Failed to set verdict: {e}");
                    }
                    continue;
                }

                // Determine direction before moving process into Connection
                let direction = if intercept_inbound {
                    if process.is_some() {
                        Direction::Outbound
                    } else {
                        Direction::Inbound
                    }
                } else {
                    Direction::Outbound
                };

                // Sniff DNS responses (UDP from port 53) to populate domain cache
                if parsed.protocol == Protocol::Udp && parsed.src_port == 53 {
                    dns_cache.parse_dns_response(&parsed.transport_payload);
                }

                // Parse HTTP request info (method, path, host)
                let http_info = http::parse_http_request(&parsed.transport_payload);

                // Extract TLS SNI for HTTPS domain
                let tls_sni = tls::extract_sni(&parsed.transport_payload);

                // Resolve hostname: TLS SNI > HTTP Host header > DNS cache
                let hostname = tls_sni.clone()
                    .or_else(|| http_info.as_ref().and_then(|h| h.host.clone()))
                    .or_else(|| dns_cache.lookup(&parsed.dst_ip));

                // Build request URL
                let dst_ip_str = parsed.dst_ip.to_string();
                let (http_method, request_url) = if let Some(ref info) = http_info {
                    let host = info.host.as_deref()
                        .or(hostname.as_deref())
                        .unwrap_or(&dst_ip_str);
                    let scheme = if parsed.dst_port == 443 { "https" } else { "http" };
                    (
                        Some(info.method.clone()),
                        Some(format!("{scheme}://{host}{}", info.path)),
                    )
                } else if let Some(ref sni) = tls_sni {
                    // HTTPS but path is encrypted
                    (None, Some(format!("https://{sni}/...")))
                } else {
                    (None, None)
                };

                // Build full payload hex
                let payload_hex = if !parsed.transport_payload.is_empty() {
                    Some(
                        parsed.transport_payload.iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(" ")
                    )
                } else {
                    None
                };

                // Build connection
                let mut conn = Connection {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    protocol: parsed.protocol,
                    src_ip: parsed.src_ip,
                    src_port: parsed.src_port,
                    dst_ip: parsed.dst_ip,
                    dst_port: parsed.dst_port,
                    process,
                    verdict: Verdict::Pending,
                    rule_id: None,
                    direction,
                    hostname,
                    http_method,
                    request_url,
                    payload_hex,
                    packet_size: parsed.packet_size,
                };

                // Evaluate rules synchronously (std::sync::RwLock -- no tokio dependency)
                let verdict = {
                    let mut engine = rule_engine.write().unwrap_or_else(|e| e.into_inner());
                    match engine.evaluate(&conn) {
                        Some((rule_id, v)) => {
                            conn.rule_id = Some(rule_id);
                            v
                        }
                        None => default_verdict,
                    }
                };
                conn.verdict = verdict;

                // Issue verdict to NFQUEUE
                let nfq_verdict = match verdict {
                    Verdict::Allow => nfq::Verdict::Accept,
                    Verdict::Deny => nfq::Verdict::Drop,
                    Verdict::Pending => nfq::Verdict::Accept,
                };
                msg.set_verdict(nfq_verdict);
                if let Err(e) = queue.verdict(msg) {
                    tracing::error!("Failed to set verdict: {e}");
                    // Don't kill the loop -- continue processing
                    continue;
                }

                // Send to async side for logging/UI (non-blocking, drop if full)
                let _ = event_tx.send(PacketEvent { connection: conn });
            }
            Err(e) => {
                consecutive_errors += 1;
                if consecutive_errors <= 3 {
                    tracing::error!("NFQUEUE recv error: {e}");
                } else if consecutive_errors == 4 {
                    tracing::error!("NFQUEUE recv errors repeating, suppressing further logs until recovery");
                }
                // Exponential backoff capped at 5 seconds
                let delay = std::cmp::min(100 * (1u64 << consecutive_errors.min(6)), 5000);
                std::thread::sleep(std::time::Duration::from_millis(delay));
            }
        }
    }
}

/// Setup iptables rules for NFQUEUE interception.
pub fn setup_iptables(
    queue_num: u16,
    outbound: bool,
    inbound: bool,
    skip_loopback: bool,
    skip_established: bool,
    fail_open: bool,
) -> Result<(), NetGuardError> {
    cleanup_iptables().ok();

    let queue_num_str = queue_num.to_string();

    // Build NFQUEUE target args
    let mut nfq_args = vec!["-j", "NFQUEUE", "--queue-num", &queue_num_str];
    if fail_open {
        nfq_args.push("--queue-bypass");
    }

    if outbound {
        run_iptables(&["-N", "NETGUARD_OUT"])?;
        if skip_loopback {
            run_iptables(&["-A", "NETGUARD_OUT", "-o", "lo", "-j", "ACCEPT"])?;
        }
        if skip_established {
            // Accept established traffic EXCEPT the first 10 packets per connection
            // This captures SYN + TLS handshake + initial data for payload inspection
            // while letting bulk data flow without userspace overhead
            let connbytes_works = run_iptables(&[
                "-A", "NETGUARD_OUT",
                "-m", "state", "--state", "ESTABLISHED,RELATED",
                "-m", "connbytes", "--connbytes", "10:", "--connbytes-dir", "both", "--connbytes-mode", "packets",
                "-j", "ACCEPT",
            ]).is_ok();
            if !connbytes_works {
                // Fallback: skip all established if connbytes module not available
                tracing::warn!("connbytes module not available, falling back to skip all established");
                run_iptables(&["-A", "NETGUARD_OUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])?;
            }
        }
        let mut out_args = vec!["-A", "NETGUARD_OUT"];
        out_args.extend_from_slice(&nfq_args);
        run_iptables(&out_args)?;
        run_iptables(&["-A", "OUTPUT", "-j", "NETGUARD_OUT"])?;
    }

    // Always intercept inbound DNS responses for domain sniffing, even if intercept_inbound is off
    {
        let _ = run_iptables(&["-N", "NETGUARD_DNS"]);
        let mut dns_args = vec!["-A", "NETGUARD_DNS", "-p", "udp", "--sport", "53"];
        dns_args.extend_from_slice(&nfq_args);
        let _ = run_iptables(&dns_args);
        // Everything else in this chain: accept
        let _ = run_iptables(&["-A", "NETGUARD_DNS", "-j", "ACCEPT"]);
        let _ = run_iptables(&["-I", "INPUT", "1", "-p", "udp", "--sport", "53", "-j", "NETGUARD_DNS"]);
    }

    if inbound {
        run_iptables(&["-N", "NETGUARD_IN"])?;
        if skip_loopback {
            run_iptables(&["-A", "NETGUARD_IN", "-i", "lo", "-j", "ACCEPT"])?;
        }
        if skip_established {
            let connbytes_works = run_iptables(&[
                "-A", "NETGUARD_IN",
                "-m", "state", "--state", "ESTABLISHED,RELATED",
                "-m", "connbytes", "--connbytes", "10:", "--connbytes-dir", "both", "--connbytes-mode", "packets",
                "-j", "ACCEPT",
            ]).is_ok();
            if !connbytes_works {
                run_iptables(&["-A", "NETGUARD_IN", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])?;
            }
        }
        let mut in_args = vec!["-A", "NETGUARD_IN"];
        in_args.extend_from_slice(&nfq_args);
        run_iptables(&in_args)?;
        run_iptables(&["-A", "INPUT", "-j", "NETGUARD_IN"])?;
    }

    tracing::info!(
        "iptables rules configured (outbound={outbound}, inbound={inbound}, fail_open={fail_open})"
    );
    Ok(())
}

/// Remove all NETGUARD iptables chains and rules.
pub fn cleanup_iptables() -> Result<(), NetGuardError> {
    let _ = run_iptables(&["-D", "OUTPUT", "-j", "NETGUARD_OUT"]);
    let _ = run_iptables(&["-D", "INPUT", "-j", "NETGUARD_IN"]);
    let _ = run_iptables(&["-F", "NETGUARD_OUT"]);
    let _ = run_iptables(&["-X", "NETGUARD_OUT"]);
    let _ = run_iptables(&["-F", "NETGUARD_IN"]);
    let _ = run_iptables(&["-X", "NETGUARD_IN"]);
    // DNS sniffing chain
    let _ = run_iptables(&["-D", "INPUT", "-p", "udp", "--sport", "53", "-j", "NETGUARD_DNS"]);
    let _ = run_iptables(&["-F", "NETGUARD_DNS"]);
    let _ = run_iptables(&["-X", "NETGUARD_DNS"]);

    tracing::info!("iptables rules cleaned up");
    Ok(())
}

fn run_iptables(args: &[&str]) -> Result<(), NetGuardError> {
    let output = std::process::Command::new("iptables")
        .args(args)
        .output()
        .map_err(|e| NetGuardError::NfQueue(format!("Failed to run iptables: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NetGuardError::NfQueue(format!(
            "iptables {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(())
}
