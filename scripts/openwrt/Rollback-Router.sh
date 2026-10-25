#!/bin/sh
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$BASE"
test -f backup/etc/config/network
/etc/init.d/swanctl stop || true
if [ "$(cat backup/swanctl.enabled)" = 0 ]; then
  /etc/init.d/swanctl disable
fi
ifdown VPN || true
ifdown VPN_XFRM || true
for f in etc/config/network etc/config/firewall etc/config/ipsec \
  etc/strongswan.d/swanbridge-xfrm.conf \
  etc/openclash/custom/openclash_custom_firewall_rules.sh \
  etc/openclash/custom/swanbridge-original-firewall.sh \
  usr/libexec/swanbridge-fw4.sh; do
  if [ -e "backup/$f" ]; then
    cp -p "backup/$f" "/$f"
  elif grep -qx "$f" backup/absent; then
    rm -f "/$f"
  fi
done
ubus call network reload
fw4 reload
printf 'VPN configuration rolled back; WAN/LAN services were not restarted.\n'
