#!/bin/bash
set -e

QUEUE_NUM=${1:-0}

# Validate queue number is numeric
if ! [[ "$QUEUE_NUM" =~ ^[0-9]+$ ]]; then
    echo "Error: queue number must be numeric, got: $QUEUE_NUM"
    exit 1
fi

echo "Setting up NFQUEUE rules (queue=$QUEUE_NUM)..."

# Clean up existing rules
iptables -D OUTPUT -j NETGUARD_OUT 2>/dev/null || true
iptables -F NETGUARD_OUT 2>/dev/null || true
iptables -X NETGUARD_OUT 2>/dev/null || true

iptables -D INPUT -j NETGUARD_IN 2>/dev/null || true
iptables -F NETGUARD_IN 2>/dev/null || true
iptables -X NETGUARD_IN 2>/dev/null || true

# Outbound chain
iptables -N NETGUARD_OUT
iptables -A NETGUARD_OUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A NETGUARD_OUT -o lo -j ACCEPT
iptables -A NETGUARD_OUT -j NFQUEUE --queue-num "$QUEUE_NUM"
iptables -A OUTPUT -j NETGUARD_OUT

# Inbound chain
iptables -N NETGUARD_IN
iptables -A NETGUARD_IN -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A NETGUARD_IN -i lo -j ACCEPT
iptables -A NETGUARD_IN -j NFQUEUE --queue-num "$QUEUE_NUM"
iptables -A INPUT -j NETGUARD_IN

echo "NFQUEUE rules configured successfully."
