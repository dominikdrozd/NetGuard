#!/bin/bash
# NetGuard deploy script — idempotent full bootstrap.
# Installs missing system deps (Rust, Node.js, libnetfilter-queue, mitmproxy),
# builds frontend + daemon, installs binary, provisions the mitmproxy user
# and confdir, resets iptables, and restarts the systemd service.
#
# Re-running this script is safe: each step checks for existing state before
# acting. It will never overwrite /etc/netguard/netguard.toml once present.
#
# Flags:
#   --enable-mitm   Also turn on HTTPS decryption end-to-end: set
#                   mitmproxy.enabled=true and allow_runtime_toggle=true
#                   in /etc/netguard/netguard.toml, and install the
#                   mitmproxy CA into the system trust store.
#                   This is invasive — browsers still need per-browser import.

set -e

ENABLE_MITM=0
for arg in "$@"; do
    case "$arg" in
        --enable-mitm) ENABLE_MITM=1 ;;
        -h|--help)
            grep -E '^#( |$)' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "unknown flag: $arg" >&2; exit 1 ;;
    esac
done

echo "=== NetGuard Deploy ==="

# ---------------------------------------------------------------------------
# Distro detection — informs which package manager we use for system deps.
# ---------------------------------------------------------------------------
if [ -r /etc/os-release ]; then
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_LIKE="${ID_LIKE:-}"
else
    DISTRO_ID="unknown"
    DISTRO_LIKE=""
fi

pkg_install() {
    case "$DISTRO_ID-$DISTRO_LIKE" in
        debian*|ubuntu*|*debian*)
            sudo apt-get install -y "$@"
            ;;
        fedora*|rhel*|centos*|*rhel*|*fedora*)
            sudo dnf install -y "$@"
            ;;
        arch*|*arch*)
            sudo pacman -S --noconfirm "$@"
            ;;
        *)
            echo "  ! Unknown distro ($DISTRO_ID). Install manually: $*"
            return 1
            ;;
    esac
}

pkg_refresh() {
    case "$DISTRO_ID-$DISTRO_LIKE" in
        debian*|ubuntu*|*debian*) sudo apt-get update -y ;;
        fedora*|rhel*|centos*|*rhel*|*fedora*) : ;;
        arch*|*arch*) sudo pacman -Sy --noconfirm ;;
    esac
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# [0/7] Ensure system build deps are present.
# ---------------------------------------------------------------------------
echo "[0/7] Checking system dependencies..."

MISSING_PKGS=()
case "$DISTRO_ID-$DISTRO_LIKE" in
    debian*|ubuntu*|*debian*)
        # Map of check-command : package-name (space-separated pairs)
        for pair in \
            "gcc:build-essential" \
            "pkg-config:pkg-config" \
            "iptables:iptables" \
            "curl:curl"; do
            cmd="${pair%%:*}"; pkg="${pair##*:}"
            if ! need_cmd "$cmd"; then MISSING_PKGS+=("$pkg"); fi
        done
        # Header packages that don't expose a binary — check via dpkg
        for lib in libnetfilter-queue-dev libnfnetlink-dev libmnl-dev; do
            if ! dpkg -s "$lib" >/dev/null 2>&1; then MISSING_PKGS+=("$lib"); fi
        done
        ;;
    fedora*|rhel*|centos*|*rhel*|*fedora*)
        for pair in "gcc:gcc" "pkg-config:pkgconfig" "iptables:iptables" "curl:curl"; do
            cmd="${pair%%:*}"; pkg="${pair##*:}"
            if ! need_cmd "$cmd"; then MISSING_PKGS+=("$pkg"); fi
        done
        for lib in libnetfilter_queue-devel libnfnetlink-devel libmnl-devel; do
            if ! rpm -q "$lib" >/dev/null 2>&1; then MISSING_PKGS+=("$lib"); fi
        done
        ;;
    arch*|*arch*)
        for pair in "gcc:base-devel" "pkg-config:pkgconf" "iptables:iptables" "curl:curl"; do
            cmd="${pair%%:*}"; pkg="${pair##*:}"
            if ! need_cmd "$cmd"; then MISSING_PKGS+=("$pkg"); fi
        done
        for lib in libnetfilter_queue libnfnetlink libmnl; do
            if ! pacman -Q "$lib" >/dev/null 2>&1; then MISSING_PKGS+=("$lib"); fi
        done
        ;;
esac

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    echo "  Installing: ${MISSING_PKGS[*]}"
    pkg_refresh || true
    pkg_install "${MISSING_PKGS[@]}"
else
    echo "  OK"
fi

# ---------------------------------------------------------------------------
# [1/7] Rust toolchain — install via rustup if cargo is missing.
# ---------------------------------------------------------------------------
echo "[1/7] Checking Rust toolchain..."
if ! need_cmd cargo; then
    echo "  Installing rustup (non-interactive, stable)..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck disable=SC1090
    . "$HOME/.cargo/env"
fi
cargo --version

# ---------------------------------------------------------------------------
# [2/7] Node.js — install via NodeSource if missing (Debian/Ubuntu) or via
# distro repo elsewhere. Minimum Node 18.
# ---------------------------------------------------------------------------
echo "[2/7] Checking Node.js..."
if ! need_cmd node || ! need_cmd npm; then
    case "$DISTRO_ID-$DISTRO_LIKE" in
        debian*|ubuntu*|*debian*)
            curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
            sudo apt-get install -y nodejs
            ;;
        fedora*|rhel*|centos*|*rhel*|*fedora*)
            sudo dnf install -y nodejs npm
            ;;
        arch*|*arch*)
            sudo pacman -S --noconfirm nodejs npm
            ;;
        *)
            echo "  ! Please install Node.js 18+ manually and re-run."; exit 1
            ;;
    esac
fi
echo "  node $(node --version) / npm $(npm --version)"

# ---------------------------------------------------------------------------
# [3/7] mitmproxy — required for optional HTTPS decryption. Prefer distro
# package; if that's missing or too old (we want >=11), fall back to the
# upstream static binary from downloads.mitmproxy.org.
# ---------------------------------------------------------------------------
echo "[3/7] Checking mitmproxy..."
if ! need_cmd mitmdump; then
    echo "  mitmdump not found; trying distro package..."
    if pkg_install mitmproxy 2>/dev/null && need_cmd mitmdump; then
        :
    else
        echo "  Falling back to upstream static binary..."
        MITM_VERSION="12.1.2"
        ARCH="$(uname -m)"
        case "$ARCH" in
            x86_64)   MITM_ARCH="x86_64" ;;
            aarch64)  MITM_ARCH="aarch64" ;;
            *) echo "  ! Unsupported arch $ARCH for upstream mitmproxy tarball."; exit 1 ;;
        esac
        MITM_URL="https://downloads.mitmproxy.org/${MITM_VERSION}/mitmproxy-${MITM_VERSION}-linux-${MITM_ARCH}.tar.gz"
        TMP="$(mktemp -d)"
        echo "  Downloading $MITM_URL"
        curl -fsSL -o "$TMP/mitm.tar.gz" "$MITM_URL"
        tar -xzf "$TMP/mitm.tar.gz" -C "$TMP"
        sudo install -m 0755 "$TMP/mitmdump"   /usr/local/bin/mitmdump
        sudo install -m 0755 "$TMP/mitmproxy" /usr/local/bin/mitmproxy
        sudo install -m 0755 "$TMP/mitmweb"   /usr/local/bin/mitmweb
        rm -rf "$TMP"
    fi
fi
echo "  $(mitmdump --version 2>/dev/null | head -n1 || echo 'mitmdump installed')"

# ---------------------------------------------------------------------------
# [4/7] Frontend build. Installs node_modules on first run.
# ---------------------------------------------------------------------------
echo "[4/7] Building frontend..."
pushd frontend >/dev/null
if [ ! -d node_modules ]; then
    echo "  Installing npm deps..."
    npm ci || npm install
fi
npm run build
popd >/dev/null

# ---------------------------------------------------------------------------
# [5/7] Cargo build (release).
# ---------------------------------------------------------------------------
echo "[5/7] Building daemon..."
cargo build --release

echo "  Installing binary to /usr/local/bin/netguard"
sudo install -m 0755 target/release/netguard /usr/local/bin/netguard

# ---------------------------------------------------------------------------
# [6/7] Provision /etc/netguard, /var/log/netguard, systemd unit, mitm user
# and confdir. Never overwrites an existing /etc/netguard/netguard.toml.
# ---------------------------------------------------------------------------
echo "[6/7] Provisioning directories and config..."
sudo install -d -o root -g root -m 0755 /etc/netguard
sudo install -d -o root -g root -m 0750 /var/log/netguard
sudo install -d -o root -g root -m 0755 /run/netguard

if [ ! -f /etc/netguard/netguard.toml ]; then
    echo "  Installing default config to /etc/netguard/netguard.toml"
    sudo install -m 0644 config/netguard.toml /etc/netguard/netguard.toml
else
    echo "  /etc/netguard/netguard.toml already exists — leaving untouched"
fi

if [ ! -f /etc/netguard/rules.json ]; then
    echo "  Seeding empty rule set at /etc/netguard/rules.json"
    echo '{"version":1,"rules":[]}' | sudo tee /etc/netguard/rules.json >/dev/null
    sudo chmod 0644 /etc/netguard/rules.json
fi

# mitmproxy system user (idempotent)
if ! id -u netguard-mitm >/dev/null 2>&1; then
    echo "  Creating netguard-mitm system user"
    sudo useradd -r -s /usr/sbin/nologin netguard-mitm
fi
sudo install -d -o netguard-mitm -g netguard-mitm -m 0750 /var/lib/netguard/mitm

# Generate the mitm CA on disk if not already there. mitmproxy only writes the
# CA when it actually starts and initializes its confdir, so we briefly launch
# mitmdump on a high unused port and kill it after a couple seconds. The CA
# is NOT installed into the system trust store here unless --enable-mitm was
# passed — see the trust block further down.
if ! sudo test -f /var/lib/netguard/mitm/mitmproxy-ca-cert.pem; then
    echo "  Bootstrapping mitmproxy CA (this may take a few seconds)..."
    # Pick a random high port so we never collide with the real mitmproxy or
    # anything else the user has running.
    BOOTSTRAP_PORT=$(( (RANDOM % 10000) + 40000 ))
    # SIGKILL after 4s. mitmdump initializes the CA before it finishes binding
    # the listener, so even if we kill it fast the cert is on disk.
    sudo -u netguard-mitm env HOME=/var/lib/netguard/mitm \
        timeout -s KILL 4 \
        mitmdump \
            --set confdir=/var/lib/netguard/mitm \
            --listen-host 127.0.0.1 \
            --listen-port "$BOOTSTRAP_PORT" \
            --mode regular \
            --set termlog_verbosity=error \
            >/dev/null 2>&1 || true
    if sudo test -f /var/lib/netguard/mitm/mitmproxy-ca-cert.pem; then
        echo "  CA generated at /var/lib/netguard/mitm/mitmproxy-ca-cert.pem"
    else
        echo "  ! CA was NOT generated. Try manually:" >&2
        echo "    sudo -u netguard-mitm HOME=/var/lib/netguard/mitm mitmdump --set confdir=/var/lib/netguard/mitm --listen-port $BOOTSTRAP_PORT" >&2
        echo "    (Ctrl+C after a few seconds)" >&2
    fi
fi

# If --enable-mitm was passed, flip the two flags in /etc/netguard/netguard.toml
# to turn on HTTPS decryption + runtime toggle, and install the CA into the
# system trust store. This section is the ONLY place deploy.sh changes an
# existing config file.
if [ "$ENABLE_MITM" = "1" ]; then
    echo "  Enabling HTTPS decryption in /etc/netguard/netguard.toml"
    # Use sed only inside the [mitmproxy] section so we don't accidentally
    # touch an 'enabled' key in a different section.
    sudo python3 - <<'PY'
import re, pathlib
p = pathlib.Path("/etc/netguard/netguard.toml")
text = p.read_text()

def set_in_section(text, section, key, value):
    # Find [section] ... until next [header] or EOF
    pattern = re.compile(rf"(\[{re.escape(section)}\](?:.|\n)*?)(?=\n\[|\Z)")
    m = pattern.search(text)
    if not m:
        # Section missing — append it
        return text.rstrip() + f"\n\n[{section}]\n{key} = {value}\n"
    block = m.group(1)
    key_re = re.compile(rf"(?m)^{re.escape(key)}\s*=.*$")
    if key_re.search(block):
        new_block = key_re.sub(f"{key} = {value}", block)
    else:
        new_block = block.rstrip() + f"\n{key} = {value}\n"
    return text[: m.start()] + new_block + text[m.end():]

text = set_in_section(text, "mitmproxy", "enabled", "true")
text = set_in_section(text, "mitmproxy", "allow_runtime_toggle", "true")
p.write_text(text)
print("  ok")
PY

    if sudo test -f /var/lib/netguard/mitm/mitmproxy-ca-cert.pem; then
        echo "  Trusting mitmproxy CA system-wide"
        sudo install -m 0644 /var/lib/netguard/mitm/mitmproxy-ca-cert.pem \
            /usr/local/share/ca-certificates/netguard-mitm.crt
        sudo update-ca-certificates >/dev/null
    else
        echo "  ! CA file missing; skipping system trust install" >&2
    fi
fi

# systemd unit (only copy if the source exists and the installed copy differs
# or is missing; never force-overwrite a user-edited override)
if [ -f systemd/netguard.service ]; then
    if ! sudo test -f /etc/systemd/system/netguard.service \
       || ! sudo cmp -s systemd/netguard.service /etc/systemd/system/netguard.service; then
        echo "  Installing systemd unit"
        sudo install -m 0644 systemd/netguard.service /etc/systemd/system/netguard.service
        sudo systemctl daemon-reload
        sudo systemctl enable netguard >/dev/null 2>&1 || true
    fi
fi

# ---------------------------------------------------------------------------
# [7/7] Reset iptables cleanly and (re)start the service.
# ---------------------------------------------------------------------------
echo "[7/7] Resetting iptables + restarting service..."
sudo iptables -F 2>/dev/null || true
sudo iptables -X 2>/dev/null || true
sudo iptables -t mangle -F 2>/dev/null || true
sudo iptables -t mangle -X 2>/dev/null || true
sudo iptables -t nat -F 2>/dev/null || true
sudo iptables -t nat -X 2>/dev/null || true
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT

sudo systemctl restart netguard

echo ""
echo "Done. Web UI at http://127.0.0.1:3031"
echo "Status:  sudo systemctl status netguard"
echo "Logs:    sudo journalctl -u netguard -f"
echo "Token:   sudo cat /etc/netguard/api_token"
echo ""
if [ "$ENABLE_MITM" = "1" ]; then
    echo "HTTPS decryption: ENABLED. The mitmproxy CA is trusted system-wide."
    echo "Browsers still need per-browser import — use the 'Download CA' button"
    echo "in the sidebar + 'How to install' helper."
    echo ""
    echo "Test it:"
    echo "  curl https://httpbin.org/get"
    echo "  # then click the connection in the web UI"
else
    echo "HTTPS decryption: DISABLED (safe default)."
    echo "To enable end-to-end, re-run:  ./deploy.sh --enable-mitm"
fi
