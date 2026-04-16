#!/bin/sh
# NetGuard package postremove — daemon-reload after unit file deletion.
#
# Intentional non-actions:
#   - Does NOT flush iptables. The daemon's ExecStopPost=netguard --cleanup
#     already ran during preremove's systemctl stop and removed NetGuard-
#     owned rules. Blanket iptables -F would wipe unrelated user rules.
#   - Does NOT remove /etc/netguard, /var/log/netguard, /var/lib/netguard.
#     These are user data. Debian `purge` removes /etc; RPM/Arch users
#     remove manually.
#   - Does NOT remove the netguard-mitm system user. Harmless to leave,
#     and removing it would orphan file ownership under /var/lib/netguard.

set -e

. /usr/share/netguard/_action.sh "$@"

echo "netguard postremove: action=$ACTION"

systemctl daemon-reload 2>/dev/null || true

exit 0
