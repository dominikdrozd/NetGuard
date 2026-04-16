#!/bin/sh
# Normalize packaging-format args into a single $ACTION var.
#
# Debian: configure | remove | purge | upgrade | failed-upgrade   (in $1)
# RPM:    1 on first install, 2 on upgrade, 0 on uninstall         (in $1)
# Arch:   no args — nfpm collapses pre_install/pre_upgrade/pre_remove fns;
#         fallback keeps Arch installs working.
#
# Sets $ACTION to one of: install | upgrade | remove
# Not executed directly — sourced by the three lifecycle scripts.

case "${1:-install}" in
    configure|1)                   ACTION=install ;;
    2|upgrade|failed-upgrade)      ACTION=upgrade ;;
    0|remove|purge)                ACTION=remove ;;
    *)                             ACTION=install ;;
esac

export ACTION
