use crate::dns::DnsCache;
use crate::packet::parse_ip_packet;
use crate::procmap::ProcMapper;
use crate::http;
use crate::tls;
use chrono::Utc;
use netguard_core::errors::NetGuardError;
use netguard_core::models::*;
use netguard_core::rule_engine::RuleEngine;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use uuid::Uuid;

/// Raw packet info sent to the async resolver for logging/prompting.
/// Each unique flow (5-tuple) produces exactly one `New` event followed by
/// zero or more `Enrich` events as later packets bring in TLS SNI, HTTP
/// request info, or payload that wasn't visible at SYN time.
#[derive(Debug)]
pub enum PacketEvent {
    New(Connection),
    Enrich { id: Uuid, delta: EnrichmentDelta },
}

/// Key used to dedupe packet events per flow. UDP flows use src+dst too, so
/// DNS responses (which we also NFQUEUE for sniffing) don't collide.
type FlowKey5 = (IpAddr, u16, IpAddr, u16, Protocol);

/// Per-flow tracking record kept in the NFQUEUE thread's local HashMap.
/// Fields marked `has_*` are set once the corresponding metadata has been
/// emitted — so we never re-send the same value twice.
struct TrackedFlow {
    uuid: Uuid,
    has_hostname: bool,
    has_http_method: bool,
    has_request_url: bool,
    has_payload: bool,
    last_seen: Instant,
}

/// Hard cap on tracked flows to bound memory if something goes wrong (a flood
/// of unique 5-tuples). When we hit this we evict by age first, then
/// wholesale clear if still oversized.
const MAX_TRACKED_FLOWS: usize = 20_000;
const TRACKED_FLOW_TTL: std::time::Duration = std::time::Duration::from_secs(600);

fn evict_tracked(seen: &mut HashMap<FlowKey5, TrackedFlow>) {
    if seen.len() <= MAX_TRACKED_FLOWS {
        return;
    }
    let cutoff = Instant::now() - TRACKED_FLOW_TTL;
    seen.retain(|_, tc| tc.last_seen > cutoff);
    if seen.len() > MAX_TRACKED_FLOWS {
        // Still over cap even after TTL evict — nuke it. Losing the dedup
        // map briefly is fine; at worst we emit a duplicate NewConnection
        // event for flows currently in flight.
        tracing::warn!("tracked-flow map exceeded cap, clearing");
        seen.clear();
    }
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
    // Dedupe map: one UUID per 5-tuple. First packet of each flow emits
    // PacketEvent::New; subsequent packets of the same flow only emit
    // PacketEvent::Enrich when they carry previously-unseen info (SNI, HTTP
    // request, non-empty payload). Reset wholesale if we blow the cap.
    let mut tracked_flows: HashMap<FlowKey5, TrackedFlow> = HashMap::new();

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

                // Dedupe by 5-tuple. First packet of a flow -> new UUID +
                // full Connection event. Subsequent packets -> reuse UUID,
                // only send an Enrich event carrying fields that weren't
                // present on earlier packets.
                let flow_key: FlowKey5 = (
                    parsed.src_ip,
                    parsed.src_port,
                    parsed.dst_ip,
                    parsed.dst_port,
                    parsed.protocol,
                );
                evict_tracked(&mut tracked_flows);
                let (is_new_flow, flow_uuid) = match tracked_flows.get_mut(&flow_key) {
                    Some(tc) => {
                        tc.last_seen = Instant::now();
                        (false, tc.uuid)
                    }
                    None => {
                        let uuid = Uuid::new_v4();
                        tracked_flows.insert(
                            flow_key,
                            TrackedFlow {
                                uuid,
                                has_hostname: hostname.is_some(),
                                has_http_method: http_method.is_some(),
                                has_request_url: request_url.is_some(),
                                has_payload: payload_hex.is_some(),
                                last_seen: Instant::now(),
                            },
                        );
                        (true, uuid)
                    }
                };

                // Build connection (used for rule evaluation on every packet —
                // rules may match on later info that wasn't in the SYN).
                let mut conn = Connection {
                    id: flow_uuid,
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
                    hostname: hostname.clone(),
                    http_method: http_method.clone(),
                    request_url: request_url.clone(),
                    payload_hex: payload_hex.clone(),
                    packet_size: parsed.packet_size,
                    decrypted_request_headers: None,
                    decrypted_request_body: None,
                    decrypted_response_status: None,
                    decrypted_response_headers: None,
                    decrypted_response_body: None,
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

                // Send to async side for logging/UI.
                if is_new_flow {
                    let _ = event_tx.send(PacketEvent::New(conn));
                } else {
                    // Only emit an enrichment if this packet brings info the
                    // original NewConnection event didn't have.
                    let tc = tracked_flows.get_mut(&flow_key).expect("just inserted");
                    let mut delta = EnrichmentDelta::default();
                    let mut has_any = false;
                    if !tc.has_hostname {
                        if let Some(h) = hostname {
                            delta.hostname = Some(h);
                            tc.has_hostname = true;
                            has_any = true;
                        }
                    }
                    if !tc.has_http_method {
                        if let Some(m) = http_method {
                            delta.http_method = Some(m);
                            tc.has_http_method = true;
                            has_any = true;
                        }
                    }
                    if !tc.has_request_url {
                        if let Some(u) = request_url {
                            delta.request_url = Some(u);
                            tc.has_request_url = true;
                            has_any = true;
                        }
                    }
                    if !tc.has_payload {
                        if let Some(p) = payload_hex {
                            delta.payload_hex = Some(p);
                            tc.has_payload = true;
                            has_any = true;
                        }
                    }
                    if has_any {
                        let _ = event_tx.send(PacketEvent::Enrich {
                            id: flow_uuid,
                            delta,
                        });
                    }
                }
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

/// Options for enabling transparent mitmproxy interception.
/// `uid` is the NUMERIC UID of the mitmproxy subprocess user, resolved once
/// at daemon startup via `netguard_core::config::resolve_system_user`. We
/// refuse to use the username form in iptables because it would be silently
/// misbehaving if the system's /etc/passwd changes (package reinstall,
/// restored backup, UID recycling).
pub struct MitmRedirect {
    pub uid: u32,
    pub port: u16,
}

/// Setup iptables rules for NFQUEUE interception.
pub fn setup_iptables(
    queue_num: u16,
    outbound: bool,
    inbound: bool,
    skip_loopback: bool,
    skip_established: bool,
    fail_open: bool,
    mitm: Option<MitmRedirect>,
) -> Result<(), NetGuardError> {
    cleanup_iptables().ok();

    let queue_num_str = queue_num.to_string();

    // Build NFQUEUE target args
    let mut nfq_args = vec!["-j", "NFQUEUE", "--queue-num", &queue_num_str];
    if fail_open {
        nfq_args.push("--queue-bypass");
    }

    if outbound {
        // NETGUARD_OUT lives in the mangle table so it runs BEFORE nat OUTPUT.
        // When mitmproxy is enabled, nat OUTPUT REDIRECTs tcp/80 and tcp/443 to 127.0.0.1:<mitm_port>;
        // placing NFQUEUE in mangle lets us still see the ORIGINAL destination.
        run_iptables(&["-t", "mangle", "-N", "NETGUARD_OUT"])?;
        // When mitmproxy is enabled, let its own upstream (re-encrypted) traffic
        // bypass NFQUEUE entirely so we don't process the same flow twice.
        if let Some(ref m) = mitm {
            let uid_str = m.uid.to_string();
            run_iptables(&[
                "-t", "mangle", "-A", "NETGUARD_OUT",
                "-m", "owner", "--uid-owner", &uid_str,
                "-j", "RETURN",
            ])?;
        }
        if skip_loopback {
            run_iptables(&["-t", "mangle", "-A", "NETGUARD_OUT", "-o", "lo", "-j", "ACCEPT"])?;
        }
        if skip_established {
            // Accept established traffic EXCEPT the first 10 packets per connection
            // This captures SYN + TLS handshake + initial data for payload inspection
            // while letting bulk data flow without userspace overhead
            let connbytes_works = run_iptables(&[
                "-t", "mangle",
                "-A", "NETGUARD_OUT",
                "-m", "state", "--state", "ESTABLISHED,RELATED",
                "-m", "connbytes", "--connbytes", "10:", "--connbytes-dir", "both", "--connbytes-mode", "packets",
                "-j", "ACCEPT",
            ]).is_ok();
            if !connbytes_works {
                // Fallback: skip all established if connbytes module not available
                tracing::warn!("connbytes module not available, falling back to skip all established");
                run_iptables(&["-t", "mangle", "-A", "NETGUARD_OUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])?;
            }
        }
        let mut out_args = vec!["-t", "mangle", "-A", "NETGUARD_OUT"];
        out_args.extend_from_slice(&nfq_args);
        run_iptables(&out_args)?;
        run_iptables(&["-t", "mangle", "-A", "OUTPUT", "-j", "NETGUARD_OUT"])?;
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

    // Transparent mitmproxy REDIRECT is deferred to setup_mitm_redirect() after
    // the mitmdump subprocess is confirmed running. owner-match RETURN rule in
    // NETGUARD_OUT above is already in place when mitm is enabled.

    tracing::info!(
        "iptables rules configured (outbound={outbound}, inbound={inbound}, fail_open={fail_open}, mitm={})",
        mitm.is_some()
    );
    Ok(())
}

/// Install the nat OUTPUT REDIRECT rules so tcp/80 and tcp/443 are steered to
/// a local mitmproxy listener. Call this only after mitmdump is actually
/// bound, otherwise outbound HTTP(S) breaks while the child is still starting.
pub fn setup_mitm_redirect(uid: u32, port: u16) -> Result<(), NetGuardError> {
    let port_str = port.to_string();
    let uid_str = uid.to_string();
    // Tolerate the chain already existing (e.g. after a crash that skipped cleanup)
    let _ = run_iptables(&["-t", "nat", "-N", "NETGUARD_REDIR"]);
    let _ = run_iptables(&["-t", "nat", "-F", "NETGUARD_REDIR"]);
    run_iptables(&[
        "-t", "nat", "-A", "NETGUARD_REDIR",
        "-m", "owner", "--uid-owner", &uid_str,
        "-j", "RETURN",
    ])?;
    run_iptables(&[
        "-t", "nat", "-A", "NETGUARD_REDIR",
        "-p", "tcp", "--dport", "80",
        "-j", "REDIRECT", "--to-ports", &port_str,
    ])?;
    run_iptables(&[
        "-t", "nat", "-A", "NETGUARD_REDIR",
        "-p", "tcp", "--dport", "443",
        "-j", "REDIRECT", "--to-ports", &port_str,
    ])?;
    // Idempotent insert (-D first ignored on first run)
    let _ = run_iptables(&["-t", "nat", "-D", "OUTPUT", "-j", "NETGUARD_REDIR"]);
    run_iptables(&["-t", "nat", "-I", "OUTPUT", "1", "-j", "NETGUARD_REDIR"])?;
    tracing::info!("mitmproxy REDIRECT active: tcp/80,443 -> 127.0.0.1:{port}");
    Ok(())
}

/// Remove all NETGUARD iptables chains and rules.
pub fn cleanup_iptables() -> Result<(), NetGuardError> {
    // NETGUARD_OUT now lives in mangle table
    let _ = run_iptables(&["-t", "mangle", "-D", "OUTPUT", "-j", "NETGUARD_OUT"]);
    let _ = run_iptables(&["-t", "mangle", "-F", "NETGUARD_OUT"]);
    let _ = run_iptables(&["-t", "mangle", "-X", "NETGUARD_OUT"]);
    // Legacy: previous versions put NETGUARD_OUT in filter table. Clean that up too
    // so upgrades don't leave stale rules behind.
    let _ = run_iptables(&["-D", "OUTPUT", "-j", "NETGUARD_OUT"]);
    let _ = run_iptables(&["-F", "NETGUARD_OUT"]);
    let _ = run_iptables(&["-X", "NETGUARD_OUT"]);

    let _ = run_iptables(&["-D", "INPUT", "-j", "NETGUARD_IN"]);
    let _ = run_iptables(&["-F", "NETGUARD_IN"]);
    let _ = run_iptables(&["-X", "NETGUARD_IN"]);
    // DNS sniffing chain
    let _ = run_iptables(&["-D", "INPUT", "-p", "udp", "--sport", "53", "-j", "NETGUARD_DNS"]);
    let _ = run_iptables(&["-F", "NETGUARD_DNS"]);
    let _ = run_iptables(&["-X", "NETGUARD_DNS"]);

    // nat NETGUARD_REDIR chain (mitmproxy REDIRECT) — cleaned up even if mitm was disabled
    let _ = run_iptables(&["-t", "nat", "-D", "OUTPUT", "-j", "NETGUARD_REDIR"]);
    let _ = run_iptables(&["-t", "nat", "-F", "NETGUARD_REDIR"]);
    let _ = run_iptables(&["-t", "nat", "-X", "NETGUARD_REDIR"]);

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
