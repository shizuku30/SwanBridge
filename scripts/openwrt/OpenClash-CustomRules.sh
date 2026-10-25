#!/bin/sh
# Preserve the user's existing hook, including its own exit statements.
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
sh "$BASE/swanbridge-original-firewall.sh"
[ ! -x /usr/libexec/swanbridge-fw4.sh ] || /usr/libexec/swanbridge-fw4.sh
exit 0
