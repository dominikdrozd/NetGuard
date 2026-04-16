#!/bin/sh
# NetGuard package postinstall — idempotent, runs as root on install + upgrade.
# Distilled from deploy.sh steps 6 (provisioning) + 7 (enable service).
# Does NOT install the mitmproxy CA into the system trust store — that is
# an explicit opt-in via the web UI / CLI (see README "Decrypting HTTPS").

set -e

. /usr/share/netguard/_action.sh "$@"

echo "netguard postinstall: action=$ACTION"

# ---- 1. System user for mitmproxy -----------------------------------------
if ! id -u netguard-mitm >/dev/null 2>&1; then
    echo "  creating netguard-mitm system user"
    useradd -r -s /usr/sbin/nologin netguard-mitm
fi

# ---- 2. Directories -------------------------------------------------------
install -d -o root -g root -m 0755 /etc/netguard
install -d -o root -g root -m 0750 /var/log/netguard
install -d -o netguard-mitm -g netguard-mitm -m 0750 /var/lib/netguard/mitm

# ---- 3. Default config — first install only ------------------------------
if [ ! -f /etc/netguard/netguard.toml ]; then
    echo "  installing default config"
    install -m 0644 /usr/share/netguard/netguard.toml /etc/netguard/netguard.toml
fi

if [ ! -f /etc/netguard/rules.json ]; then
    echo "  seeding empty rule set"
    printf '{"version":1,"rules":[]}\n' > /etc/netguard/rules.json
    chmod 0644 /etc/netguard/rules.json
fi

# ---- 4. Bootstrap mitmproxy CA (does NOT touch system trust) -------------
if [ ! -f /var/lib/netguard/mitm/mitmproxy-ca-cert.pem ]; then
    echo "  bootstrapping mitmproxy CA"
    BOOTSTRAP_PORT=$(awk 'BEGIN{srand(); print int(40000 + rand()*9999)}')
    sudo -u netguard-mitm env HOME=/var/lib/netguard/mitm \
        timeout -s KILL 4 \
        mitmdump \
            --set confdir=/var/lib/netguard/mitm \
            --listen-host 127.0.0.1 \
            --listen-port "$BOOTSTRAP_PORT" \
            --mode regular \
            --set termlog_verbosity=error \
            >/dev/null 2>&1 || true
    if [ -f /var/lib/netguard/mitm/mitmproxy-ca-cert.pem ]; then
        echo "  CA generated"
    else
        echo "  ! CA bootstrap failed — enable mitm from the UI to retry" >&2
    fi
fi

# ---- 5. Enable + start the service ---------------------------------------
systemctl daemon-reload
if [ "$ACTION" = "install" ]; then
    systemctl enable --now netguard.service
else
    # upgrade — restart if already enabled, but don't force-enable
    systemctl try-restart netguard.service || true
fi

echo "netguard postinstall: done"
echo "Web UI at http://127.0.0.1:$(awk -F'=' '/^listen_port/{gsub(/ /,"",$2); print $2; exit}' /etc/netguard/netguard.toml) (port may differ if in use; check journalctl -u netguard)"
