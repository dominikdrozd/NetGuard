#!/bin/bash
set -e

echo "=== NetGuard Deploy ==="

# Build frontend
echo "[1/6] Building frontend..."
cd frontend && npm run build 2>&1 && cd ..

# Build Rust
echo "[2/6] Building daemon..."
cargo build --release 2>&1

# Install binary
echo "[3/6] Installing binary..."
sudo cp target/release/netguard /usr/local/bin/netguard

# Provision mitmproxy prerequisites (user, confdir, CA). The CA is NOT
# installed into the system trust store here -- that's an opt-in step,
# documented in README under "Decrypting HTTPS content".
echo "[4/6] Provisioning mitmproxy user + confdir (CA install is opt-in)..."
if ! id -u netguard-mitm >/dev/null 2>&1; then
    sudo useradd -r -s /usr/sbin/nologin netguard-mitm
fi
sudo install -d -o netguard-mitm -g netguard-mitm -m 0750 /var/lib/netguard/mitm
sudo install -d -o root -g root -m 0755 /run/netguard
# Generate the CA on disk (not trusted yet). --help is enough to trigger first-run
# confdir bootstrap without binding a port.
if ! sudo test -f /var/lib/netguard/mitm/mitmproxy-ca-cert.pem; then
    if command -v mitmdump >/dev/null 2>&1; then
        sudo -u netguard-mitm HOME=/var/lib/netguard/mitm mitmdump --set confdir=/var/lib/netguard/mitm --help >/dev/null 2>&1 || true
    else
        echo "  WARNING: mitmdump not found. Install with: sudo apt install mitmproxy"
    fi
fi

# Clean iptables
echo "[5/6] Cleaning iptables..."
sudo iptables -F 2>/dev/null || true
sudo iptables -X 2>/dev/null || true
sudo iptables -t mangle -F 2>/dev/null || true
sudo iptables -t mangle -X 2>/dev/null || true
sudo iptables -t nat -F 2>/dev/null || true
sudo iptables -t nat -X 2>/dev/null || true
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT

# Restart service
echo "[6/6] Restarting service..."
sudo systemctl restart netguard

echo ""
echo "Done! Web UI at http://127.0.0.1:3031"
echo "Status: sudo systemctl status netguard"
echo ""
echo "HTTPS decryption is DISABLED by default."
echo "To enable, see README.md section 'Decrypting HTTPS content'."
