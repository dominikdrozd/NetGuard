#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/netguard"
LOG_DIR="/var/log/netguard"
BINARY="$PROJECT_DIR/target/release/netguard"

if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found at $BINARY"
    echo "Run 'cargo build --release' first."
    exit 1
fi

echo "Installing NetGuard..."

# Copy binary
sudo install -m 755 "$BINARY" "$INSTALL_DIR/netguard"
echo "  Binary installed to $INSTALL_DIR/netguard"

# Create config directory
sudo mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/netguard.toml" ]; then
    sudo cp "$PROJECT_DIR/config/netguard.toml" "$CONFIG_DIR/netguard.toml"
    echo "  Config installed to $CONFIG_DIR/netguard.toml"
else
    echo "  Config already exists, skipping"
fi

# Create empty rules file if needed
if [ ! -f "$CONFIG_DIR/rules.json" ]; then
    echo '{"version":1,"rules":[]}' | sudo tee "$CONFIG_DIR/rules.json" > /dev/null
    echo "  Empty rules file created"
fi

# Create log directory
sudo mkdir -p "$LOG_DIR"
echo "  Log directory created at $LOG_DIR"

# Install systemd service
sudo cp "$PROJECT_DIR/systemd/netguard.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable netguard
echo "  systemd service installed and enabled"

echo ""
echo "Installation complete!"
echo "  Start:   sudo systemctl start netguard"
echo "  Stop:    sudo systemctl stop netguard"
echo "  Status:  sudo systemctl status netguard"
echo "  Logs:    sudo journalctl -u netguard -f"
echo "  Web UI:  http://127.0.0.1:3031"
