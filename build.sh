#!/bin/bash
set -e

echo "======================================"
echo "  NetGuard - Linux Application Firewall"
echo "  Build Script"
echo "======================================"
echo ""

# Check if we're on Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo "ERROR: NetGuard can only be built on Linux."
    exit 1
fi

# Check for required system dependencies
echo "[1/5] Checking system dependencies..."

MISSING_DEPS=()

# Check for Rust/Cargo
if ! command -v cargo &> /dev/null; then
    echo "  ERROR: Rust/Cargo not found."
    echo "  Install with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi
echo "  Rust: $(rustc --version)"
echo "  Cargo: $(cargo --version)"

# Check for required C libraries
check_lib() {
    if pkg-config --exists "$1" 2>/dev/null; then
        echo "  $1: found"
    else
        echo "  $1: NOT FOUND"
        MISSING_DEPS+=("$1")
    fi
}

if command -v pkg-config &> /dev/null; then
    check_lib "libnetfilter_queue"
    check_lib "libnfnetlink"
    check_lib "libmnl"
else
    echo "  pkg-config not found, checking headers directly..."
    # Fallback: check for header files
    for header in "/usr/include/libnetfilter_queue/libnetfilter_queue.h" \
                  "/usr/include/libnfnetlink/libnfnetlink.h" \
                  "/usr/include/libmnl/libmnl.h"; do
        if [ -f "$header" ]; then
            echo "  $(basename $(dirname $header)): found"
        else
            echo "  $(basename $(dirname $header)): NOT FOUND"
            MISSING_DEPS+=("$(basename $(dirname $header))")
        fi
    done
fi

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo ""
    echo "Missing dependencies: ${MISSING_DEPS[*]}"
    echo ""
    echo "Install them with:"
    echo ""
    # Detect distro
    if [ -f /etc/debian_version ]; then
        echo "  sudo apt install -y libnetfilter-queue-dev libnfnetlink-dev libmnl-dev pkg-config build-essential"
    elif [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then
        echo "  sudo dnf install -y libnetfilter_queue-devel libnfnetlink-devel libmnl-devel pkgconfig gcc"
    elif [ -f /etc/arch-release ]; then
        echo "  sudo pacman -S libnetfilter_queue libnfnetlink libmnl pkgconf base-devel"
    else
        echo "  Install the development packages for: libnetfilter_queue, libnfnetlink, libmnl"
    fi
    echo ""
    read -p "Attempt to install automatically? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ -f /etc/debian_version ]; then
            sudo apt update && sudo apt install -y libnetfilter-queue-dev libnfnetlink-dev libmnl-dev pkg-config build-essential
        elif [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then
            sudo dnf install -y libnetfilter_queue-devel libnfnetlink-devel libmnl-devel pkgconfig gcc
        elif [ -f /etc/arch-release ]; then
            sudo pacman -S --noconfirm libnetfilter_queue libnfnetlink libmnl pkgconf base-devel
        else
            echo "Cannot auto-install on this distro. Please install manually."
            exit 1
        fi
    else
        echo "Please install the missing dependencies and re-run this script."
        exit 1
    fi
fi

# Check for iptables
if ! command -v iptables &> /dev/null; then
    echo "  WARNING: iptables not found. Required at runtime."
    echo "  Install with: sudo apt install iptables (Debian/Ubuntu)"
fi

echo ""
echo "[2/5] Building in release mode..."
cargo build --release 2>&1

BINARY="target/release/netguard"
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Build failed - binary not found."
    exit 1
fi

echo ""
echo "[3/5] Build successful!"
echo "  Binary: $BINARY"
echo "  Size: $(du -h $BINARY | cut -f1)"
echo ""

echo "[4/5] Running tests..."
cargo test -p netguard-core 2>&1 || echo "  WARNING: Some tests failed."

echo ""
echo "[5/5] Build complete!"
echo ""
echo "======================================"
echo "  Next steps:"
echo "======================================"
echo ""
echo "  Quick start (run directly):"
echo "    sudo $BINARY --config config/netguard.toml"
echo ""
echo "  Install as system service:"
echo "    sudo bash scripts/install.sh"
echo ""
echo "  Web UI will be available at:"
echo "    http://127.0.0.1:3031"
echo ""
