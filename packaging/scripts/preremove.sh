#!/bin/sh
# NetGuard package preremove — stops the service cleanly. Disables it only
# on full removal, not on upgrade.

set -e

. /usr/share/netguard/_action.sh "$@"

echo "netguard preremove: action=$ACTION"

# Stop is best-effort — never fail a removal because the service was
# already dead.
systemctl stop netguard.service 2>/dev/null || true

# Disable only on full removal; on upgrade systemctl re-enables after the
# new unit is dropped in.
if [ "$ACTION" = "remove" ]; then
    systemctl disable netguard.service 2>/dev/null || true
fi

exit 0
