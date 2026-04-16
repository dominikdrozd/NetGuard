#!/bin/bash
set -e

echo "=== NetGuard Deploy ==="

# Build frontend
echo "[1/5] Building frontend..."
cd frontend && npm run build 2>&1 && cd ..

# Build Rust
echo "[2/5] Building daemon..."
cargo build --release 2>&1

# Install binary
echo "[3/5] Installing binary..."
sudo cp target/release/netguard /usr/local/bin/netguard

# Clean iptables
echo "[4/5] Cleaning iptables..."
sudo iptables -F 2>/dev/null || true
sudo iptables -X 2>/dev/null || true
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT

# Restart service
echo "[5/5] Restarting service..."
sudo systemctl restart netguard

echo ""
echo "Done! Web UI at http://127.0.0.1:3031"
echo "Status: sudo systemctl status netguard"
