use clap::Parser;
use netguard_core::config::AppConfig;
use netguard_core::connection_log::ConnectionLog;
use netguard_core::models::*;
use netguard_core::rule_engine::RuleEngine;
use netguard_nfq::dns::DnsCache;
use netguard_nfq::procmap::ProcMapper;
use netguard_nfq::queue::{self, PacketEvent};
use netguard_nfq::resolver;
use netguard_web::server;
use netguard_web::state::AppState;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, Notify, RwLock};

#[derive(Parser)]
#[command(name = "netguard", about = "NetGuard - Linux Application Firewall")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/netguard/netguard.toml")]
    config: PathBuf,

    /// Clean up iptables rules and exit
    #[arg(long)]
    cleanup: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Handle cleanup mode
    if cli.cleanup {
        queue::cleanup_iptables()?;
        println!("iptables rules cleaned up");
        return Ok(());
    }

    // Load config
    let config = if cli.config.exists() {
        AppConfig::load(&cli.config)?
    } else {
        eprintln!("Config file not found at {:?}, using defaults", cli.config);
        AppConfig::default()
    };

    // Initialize logging
    let log_level = config
        .daemon
        .log_level
        .parse()
        .unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt().with_max_level(log_level).init();

    tracing::info!("NetGuard starting...");

    // Check root privileges
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            tracing::error!("NetGuard must run as root (need NET_ADMIN capability)");
            std::process::exit(1);
        }
    }

    // Parse default verdict
    let default_verdict = match config.daemon.default_verdict.as_str() {
        "allow" => Verdict::Allow,
        "deny" => Verdict::Deny,
        other => {
            tracing::warn!(
                "Unrecognized default_verdict '{other}', defaulting to 'deny'"
            );
            Verdict::Deny
        }
    };

    // Load or generate API token (cryptographically random)
    let api_token = load_or_generate_token(&config.web.auth_token_file)?;
    tracing::info!("API token loaded from {}", config.web.auth_token_file);

    // Load rule engine (std::sync::RwLock for NFQUEUE thread compatibility)
    let rules_path = config.rules_path();
    let rule_engine = Arc::new(std::sync::RwLock::new(
        RuleEngine::load(&rules_path, default_verdict).unwrap_or_else(|e| {
            tracing::warn!("Failed to load rules: {e}, starting with empty ruleset");
            RuleEngine::new(rules_path, default_verdict)
        }),
    ));

    // Create connection log
    let connection_log = Arc::new(ConnectionLog::new(config.logging.max_memory_entries));

    // Create channels
    let (ws_broadcast_tx, _) = broadcast::channel::<WsEvent>(4096);
    let (prompt_response_tx, prompt_response_rx) = mpsc::channel::<PromptResponse>(256);
    let pending_prompts: Arc<RwLock<HashMap<uuid::Uuid, PendingPrompt>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Create app state for web server
    let app_state = AppState {
        rule_engine: rule_engine.clone(),
        connection_log: connection_log.clone(),
        pending_prompts: pending_prompts.clone(),
        prompt_response_tx,
        ws_broadcast_tx: ws_broadcast_tx.clone(),
        api_token: api_token.clone(),
        listen_port: config.web.listen_port,
        auth_attempts: Arc::new(std::sync::Mutex::new(Vec::new())),
        ws_tickets: Arc::new(std::sync::Mutex::new(HashMap::new())),
    };

    // Setup iptables
    queue::setup_iptables(
        config.daemon.queue_num,
        config.network.intercept_outbound,
        config.network.intercept_inbound,
        config.network.skip_loopback,
        config.network.skip_established,
        config.network.fail_open,
    )?;

    // Graceful shutdown signal
    let shutdown = Arc::new(Notify::new());

    // Handle SIGTERM/SIGINT
    #[cfg(target_os = "linux")]
    {
        let shutdown_clone = shutdown.clone();
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut sigint =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        tokio::spawn(async move {
            tokio::select! {
                _ = sigterm.recv() => {},
                _ = sigint.recv() => {},
            }
            tracing::info!("Signal received, initiating shutdown...");
            shutdown_clone.notify_one();
        });
    }

    // Start process mapper cache refresh loop
    let proc_mapper = Arc::new(ProcMapper::new(config.proc.cache_refresh_ms));
    let proc_mapper_clone = proc_mapper.clone();
    tokio::spawn(async move {
        proc_mapper_clone.run_cache_refresh_loop().await;
    });

    // Bridge channel: NFQUEUE thread (std::sync) -> async event processor (tokio)
    let (std_event_tx, std_event_rx) = std::sync::mpsc::channel::<PacketEvent>();
    let (tokio_event_tx, tokio_event_rx) = mpsc::channel::<PacketEvent>(4096);

    // Spawn bridge thread: forwards from std channel to tokio channel
    std::thread::Builder::new()
        .name("nfq-bridge".into())
        .spawn(move || {
            while let Ok(event) = std_event_rx.recv() {
                if tokio_event_tx.blocking_send(event).is_err() {
                    break;
                }
            }
        })?;

    // Start NFQUEUE thread (evaluates rules synchronously, issues verdicts inline)
    let queue_num = config.daemon.queue_num;
    let nfq_rule_engine = rule_engine.clone();
    let nfq_proc_mapper = proc_mapper.clone();
    let nfq_whitelist = config.network.whitelist.clone();
    let nfq_intercept_inbound = config.network.intercept_inbound;
    let dns_cache = Arc::new(DnsCache::new(600)); // 10 minute DNS cache TTL
    let nfq_dns_cache = dns_cache.clone();
    std::thread::Builder::new()
        .name("nfq-loop".into())
        .spawn(move || {
            if let Err(e) = queue::run_nfqueue_loop(
                queue_num,
                nfq_rule_engine,
                nfq_proc_mapper,
                std_event_tx,
                default_verdict,
                nfq_whitelist,
                nfq_intercept_inbound,
                nfq_dns_cache,
            ) {
                tracing::error!("NFQUEUE loop failed: {e}");
            }
        })?;

    // Drain prompt responses to keep the channel alive.
    // Rule creation from prompts is handled directly in the API/WS handlers.
    // This task logs responses for auditing.
    tokio::spawn(async move {
        let mut rx = prompt_response_rx;
        while let Some(response) = rx.recv().await {
            tracing::info!(
                "Prompt {} resolved: {:?}",
                response.prompt_id,
                response.verdict
            );
        }
    });

    // Start async event processor (logging + UI broadcast + DNS resolution)
    let event_broadcast_tx = ws_broadcast_tx.clone();
    let event_log = connection_log.clone();
    let event_dns_cache = dns_cache.clone();
    tokio::spawn(async move {
        resolver::run_event_processor(tokio_event_rx, event_broadcast_tx, event_log, event_dns_cache).await;
    });

    // Start web server (runs until shutdown)
    let shutdown_clone = shutdown.clone();
    let web_addr = config.web.listen_addr.clone();
    let web_port = config.web.listen_port;

    tracing::info!("Starting web UI at http://{web_addr}:{web_port}");

    tokio::select! {
        result = server::start_server(app_state, &web_addr, web_port) => {
            if let Err(e) = result {
                tracing::error!("Web server error: {e}");
            }
        }
        _ = shutdown_clone.notified() => {
            tracing::info!("Shutdown signal received");
        }
    }

    // Cleanup
    tracing::info!("Cleaning up iptables rules...");
    let _ = queue::cleanup_iptables();
    tracing::info!("NetGuard stopped.");

    Ok(())
}

fn load_or_generate_token(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let token_path = std::path::Path::new(path);

    if token_path.exists() {
        let token = std::fs::read_to_string(token_path)?.trim().to_string();
        if !token.is_empty() {
            return Ok(token);
        }
    }

    // Generate a cryptographically random 32-byte token (256 bits)
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    let token = hex::encode(bytes);

    if let Some(parent) = token_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(token_path, &token)?;

    // Restrict permissions (readable only by root)
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(token_path, std::fs::Permissions::from_mode(0o600))?;
    }

    tracing::info!("Generated new API token at {path}");
    Ok(token)
}
