#!/bin/sh
set -eu
umask 077
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$BASE"
test ! -e backup
mkdir -m 700 backup
for f in etc/config/network etc/config/firewall etc/config/ipsec \
  etc/strongswan.d/swanbridge-xfrm.conf \
  etc/openclash/custom/openclash_custom_firewall_rules.sh \
  etc/openclash/custom/swanbridge-original-firewall.sh \
  usr/libexec/swanbridge-fw4.sh; do
  if [ -e "/$f" ]; then
    mkdir -p "backup/$(dirname "$f")"
    cp -p "/$f" "backup/$f"
  else
    printf '%s\n' "$f" >> backup/absent
  fi
done
ip -4 route show table main > backup/routes.before
ip -4 rule show > backup/rules.before
ubus call network.interface.wan status > backup/wan.before
apk list --installed > backup/packages.before
if /etc/init.d/swanctl enabled; then
  printf '1\n' > backup/swanctl.enabled
else
  printf '0\n' > backup/swanctl.enabled
fi
printf 'Backup ready: %s/backup\n' "$BASE"
