# NetGuard - Linux Application Firewall

A per-process network firewall for Linux, similar to [Little Snitch](https://obdev.at/products/littlesnitch-linux/index.html). Monitors all network connections in real time, shows which application is making each connection, and lets you allow or block traffic per-app via a web dashboard.

## Features

- **Real-time connection monitoring** -- see every network connection with the owning process, domain, protocol, port, and packet payload
- **Per-application firewall rules** -- allow or deny traffic based on application path, destination IP/CIDR/hostname, port, protocol, and direction
- **Interactive prompts** -- get notified when an unknown application tries to connect and decide to allow or block
- **DNS sniffing** -- automatically resolves destination IPs to domain names by capturing DNS responses
- **Packet inspection** -- click any connection to view full details including a hex+ASCII payload dump
- **Connection logging** -- searchable history with CSV export
- **Web dashboard** -- clean browser-based UI at `http://127.0.0.1:3031`
- **Fail-closed by default** -- blocks all traffic if the daemon stops (configurable)

## Architecture

```
┌──────────────┐    WebSocket/REST     ┌──────────────┐
│  Web UI      │ <──────────────────> │  Axum Server  │
│  (Browser)   │    localhost:3031     │              │
└──────────────┘                       └──────┬───────┘
                                              │
                                       ┌──────┴───────┐
                                       │  NFQUEUE      │
                                       │  Thread       │
                                       │  (verdicts)   │
                                       └──┬────┬───────┘
                                          │    │
                                ┌─────────┘    └─────────┐
                                ▼                        ▼
                         ┌────────────┐          ┌────────────┐
                         │ Rule Engine│          │ Process    │
                         │ (match +   │          │ Mapper     │
                         │  verdict)  │          │ (/proc)    │
                         └────────────┘          └────────────┘
```

Packets are intercepted by the Linux kernel via **NFQUEUE** (netfilter), evaluated against rules synchronously on a dedicated OS thread, and verdicts (accept/drop) are issued inline before the packet is released. A separate async pipeline handles logging, WebSocket broadcasting, and the web UI.

## Requirements

### Operating System

- **Linux** (x86_64 or aarch64)
- Kernel **2.6.14** or newer (for NFQUEUE support)
- Tested on: Debian 12+, Ubuntu 22.04+, Fedora 38+, Arch Linux

### System Dependencies

| Package | Debian/Ubuntu | Fedora/RHEL | Arch Linux |
|---------|--------------|-------------|------------|
| C compiler | `build-essential` | `gcc` | `base-devel` |
| pkg-config | `pkg-config` | `pkgconfig` | `pkgconf` |
| libnetfilter_queue | `libnetfilter-queue-dev` | `libnetfilter_queue-devel` | `libnetfilter_queue` |
| libnfnetlink | `libnfnetlink-dev` | `libnfnetlink-devel` | `libnfnetlink` |
| libmnl | `libmnl-dev` | `libmnl-devel` | `libmnl` |
| iptables | `iptables` | `iptables` | `iptables` |

### Rust Toolchain

- Rust **1.75** or newer
- Install from [rustup.rs](https://rustup.rs):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  source ~/.cargo/env
  ```

## Installation

### Quick Install (Debian/Ubuntu)

```bash
# 1. Install system dependencies
sudo apt update
sudo apt install -y build-essential pkg-config libnetfilter-queue-dev \
    libnfnetlink-dev libmnl-dev iptables

# 2. Build
cargo build --release

# 3. Create directories and config
sudo mkdir -p /etc/netguard /var/log/netguard
sudo cp config/netguard.toml /etc/netguard/netguard.toml
echo '{"version":1,"rules":[]}' | sudo tee /etc/netguard/rules.json > /dev/null

# 4. Run
sudo ./target/release/netguard --config /etc/netguard/netguard.toml
```

### Quick Install (Fedora/RHEL)

```bash
sudo dnf install -y gcc pkgconfig libnetfilter_queue-devel \
    libnfnetlink-devel libmnl-devel iptables
cargo build --release
sudo mkdir -p /etc/netguard /var/log/netguard
sudo cp config/netguard.toml /etc/netguard/netguard.toml
echo '{"version":1,"rules":[]}' | sudo tee /etc/netguard/rules.json > /dev/null
sudo ./target/release/netguard --config /etc/netguard/netguard.toml
```

### Quick Install (Arch Linux)

```bash
sudo pacman -S base-devel pkgconf libnetfilter_queue libnfnetlink libmnl iptables
cargo build --release
sudo mkdir -p /etc/netguard /var/log/netguard
sudo cp config/netguard.toml /etc/netguard/netguard.toml
echo '{"version":1,"rules":[]}' | sudo tee /etc/netguard/rules.json > /dev/null
sudo ./target/release/netguard --config /etc/netguard/netguard.toml
```

### Using the Build Script

The included build script automates dependency checking:

```bash
chmod +x build.sh
./build.sh
```

### Install as systemd Service

```bash
sudo bash scripts/install.sh
sudo systemctl start netguard
```

This installs the binary to `/usr/local/bin/netguard`, copies the config, and enables the systemd service.

## Usage

### Starting the Daemon

```bash
# Run directly
sudo ./target/release/netguard --config /etc/netguard/netguard.toml

# Or via systemd
sudo systemctl start netguard
```

### Accessing the Web UI

Open **http://127.0.0.1:3031** in your browser.

On first launch, you need to authenticate with the API token:

```bash
sudo cat /etc/netguard/api_token
```

Paste the token into the login screen. The token is stored in your browser's session storage and cleared when you close the tab.

### Managing the Service

```bash
sudo systemctl start netguard      # Start
sudo systemctl stop netguard       # Stop
sudo systemctl restart netguard    # Restart
sudo systemctl status netguard     # Check status
sudo journalctl -u netguard -f    # View live logs
```

### Cleaning Up iptables Rules

If the daemon stops unexpectedly and iptables rules remain:

```bash
sudo netguard --cleanup
```

## Configuration

Edit `/etc/netguard/netguard.toml`:

```toml
[daemon]
queue_num = 0                  # NFQUEUE number
default_verdict = "deny"       # "allow" or "deny" for unknown connections
prompt_timeout = 15            # Seconds to wait for user prompt response
log_level = "info"             # trace, debug, info, warn, error

[web]
listen_addr = "127.0.0.1"     # Bind address (use 127.0.0.1 for local only)
listen_port = 3031             # Web UI port
auth_token_file = "/etc/netguard/api_token"

[rules]
rules_file = "/etc/netguard/rules.json"

[logging]
log_file = "/var/log/netguard/connections.log"
max_memory_entries = 10000     # Max connections kept in memory for the UI

[network]
intercept_outbound = true      # Monitor outgoing connections
intercept_inbound = false      # Monitor incoming connections
skip_loopback = true           # Ignore localhost traffic
skip_established = true        # Only intercept new connections
fail_open = false              # If true, traffic flows when daemon is down
whitelist = [                  # Apps that bypass the firewall
    "/usr/lib/systemd/systemd-resolved",
    "/usr/lib/systemd/systemd-timesyncd",
]

[proc]
cache_refresh_ms = 2000        # Process-to-socket cache refresh interval
```

### Key Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `default_verdict` | `deny` | What to do when no rule matches. `deny` = block unknown connections. `allow` = permit unknown connections. |
| `fail_open` | `false` | If `false` (fail-closed), ALL traffic is blocked when the daemon is not running. Set to `true` while testing. |
| `intercept_inbound` | `false` | Enable to also monitor incoming connections. |
| `listen_addr` | `127.0.0.1` | Change to `0.0.0.0` to access the UI from other machines (not recommended). |

## Web Dashboard

### Dashboard
Overview with live connection stream, stats (allowed/denied/connections per second), and top applications.

### Connections
Filterable table of all connections showing time, application, domain, destination, port, protocol, size, and verdict. Click any row to open the **packet detail view** with:
- Full process info (path, command line, PID, username)
- Resolved domain name
- Source and destination addresses
- Hex + ASCII payload dump

### Rules
Create, edit, delete, toggle, and reorder firewall rules. Rules support:
- Application path matching (exact or glob: `/usr/lib/firefox/*`)
- Destination matching (IP, CIDR `10.0.0.0/8`, hostname pattern `*.example.com`)
- Port and protocol filtering
- Direction (inbound/outbound/both)
- Temporary rules with expiration

### Prompts
When an unknown application makes a connection and `default_verdict = "deny"`, a prompt appears asking you to allow or deny. You can choose:
- **Allow/Deny Once** -- one-time decision
- **Allow/Deny & Remember** -- creates a persistent rule with configurable scope (this destination, this port, or anywhere)

### Logs
Searchable connection history with CSV export.

## Security

- **Authentication**: All API endpoints require a Bearer token. Token is auto-generated (256-bit cryptographic random) and stored at `/etc/netguard/api_token` with root-only permissions (0600).
- **Constant-time token comparison**: Prevents timing side-channel attacks.
- **CORS**: Restricted to same-origin only.
- **WebSocket**: Uses one-time tickets (not long-lived tokens) with Origin header validation.
- **Rate limiting**: Token validation endpoint is rate-limited (10 attempts per 60 seconds).
- **XSS protection**: All dynamic content is HTML-escaped. Content-Security-Policy headers enforced.
- **Atomic file writes**: Rules are written to a temp file then renamed to prevent corruption.
- **Fail-closed**: By default, traffic is blocked if the daemon crashes.

## Project Structure

```
netguard/
├── Cargo.toml                 # Workspace root
├── config/netguard.toml       # Default configuration
├── systemd/netguard.service   # systemd unit file
├── scripts/
│   ├── install.sh             # System installation script
│   └── setup-nfqueue.sh       # Manual iptables setup
├── build.sh                   # Build script with dependency checking
└── crates/
    ├── netguard-core/         # Data types, rule engine, config (cross-platform)
    ├── netguard-nfq/          # NFQUEUE, packet parsing, process mapping, DNS cache (Linux)
    ├── netguard-web/          # Axum web server, REST API, WebSocket, embedded SPA
    └── netguard-daemon/       # Binary entry point, orchestration
```

## Troubleshooting

### "NetGuard must run as root"
The daemon needs `CAP_NET_ADMIN` capability for NFQUEUE and iptables. Run with `sudo`.

### Network stopped working after stopping NetGuard
With `fail_open = false` (default), stopping the daemon blocks traffic because the NFQUEUE rules remain. Fix:
```bash
sudo netguard --cleanup
# or manually:
sudo iptables -D OUTPUT -j NETGUARD_OUT
sudo iptables -D INPUT -j NETGUARD_IN
sudo iptables -F NETGUARD_OUT && sudo iptables -X NETGUARD_OUT
sudo iptables -F NETGUARD_IN && sudo iptables -X NETGUARD_IN
```

### Everything is being blocked
Check your `default_verdict` setting. If set to `deny`, all connections without a matching allow rule are blocked. Either:
- Set `default_verdict = "allow"` to allow by default
- Create allow rules for your applications via the web UI

### Can't access the web UI
- Verify the daemon is running: `sudo systemctl status netguard`
- Check the port: `curl http://127.0.0.1:3031`
- Check logs: `sudo journalctl -u netguard -f`

### "Permission denied" building on Linux
Ensure development packages are installed (see Requirements above).

## License

MIT
