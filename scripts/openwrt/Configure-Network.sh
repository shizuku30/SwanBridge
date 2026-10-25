#!/bin/sh
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$BASE"
test -f backup/etc/config/network
test "$(uci -q get ipsec.sb_roadwarrior.enabled)" = 1
test -e /sys/module/xfrm_interface
cp xfrm-routing.conf /etc/strongswan.d/swanbridge-xfrm.conf
mkdir -p /usr/libexec
cp swanbridge-fw4.sh /usr/libexec/swanbridge-fw4.sh
chmod 755 /usr/libexec/swanbridge-fw4.sh
test ! -e /etc/openclash/custom/swanbridge-original-firewall.sh
cp -p /etc/openclash/custom/openclash_custom_firewall_rules.sh \
  /etc/openclash/custom/swanbridge-original-firewall.sh
cp OpenClash-CustomRules.sh /etc/openclash/custom/openclash_custom_firewall_rules.sh
chmod 755 /etc/openclash/custom/openclash_custom_firewall_rules.sh
uci batch <<'EOF'
set network.VPN_XFRM=interface
set network.VPN_XFRM.proto='xfrm'
set network.VPN_XFRM.ifid='42'
set network.VPN_XFRM.mtu='1280'
set network.VPN_XFRM.multicast='0'
set network.VPN.device='VPN_XFRM'
set firewall.swanbridge_bypass=include
set firewall.swanbridge_bypass.type='script'
set firewall.swanbridge_bypass.path='/usr/libexec/swanbridge-fw4.sh'
set firewall.swanbridge_bypass.fw4_compatible='1'
commit network
commit firewall
EOF
fw4 check
ubus call network reload
sleep 3
if [ -n "$(ubus call network get_proto_handlers | jsonfilter -e '@.xfrm')" ]; then
  ifup VPN_XFRM
else
  # New protocols are registered only at netifd startup; do not restart WAN.
  ip link show VPN_XFRM >/dev/null 2>&1 || ip link add VPN_XFRM type xfrm if_id 42
  ip link set VPN_XFRM mtu 1280 up
fi
ifup VPN
sleep 3
fw4 reload
sh /usr/libexec/swanbridge-fw4.sh
ubus call network.interface.VPN status | jsonfilter -e '@.up' | grep -qx true
/etc/init.d/swanctl enable
/etc/init.d/swanctl restart
ip -4 route show default
ubus call network.interface.wan status | grep -E '("up"|"uptime"|"l3_device")'
printf 'Only VPN interfaces and firewall were reloaded.\n'
