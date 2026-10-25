#!/bin/sh
set -eu
serial=$(cat /sys/class/block/vdb/serial 2>/dev/null || true)
test "$serial" = SB-BUILD-DATA
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB=/build/ike-lab
test ! -e "$LAB"
test -d "$BASE/sdk/build_dir/target-x86_64_musl/strongswan-6.1.0/.pkgdir"
mkdir -m 700 "$LAB"
server_pid= client_pid=
cleanup() {
  for role in server client; do
    ip -n "sb-lab-$role" addr show > "$LAB/$role-addresses.txt" 2>&1 || true
    ip -n "sb-lab-$role" route show table all > "$LAB/$role-routes.txt" 2>&1 || true
    ip -n "sb-lab-$role" -s xfrm state > "$LAB/$role-xfrm-states.txt" 2>&1 || true
    ip -n "sb-lab-$role" -s xfrm policy > "$LAB/$role-xfrm-policies.txt" 2>&1 || true
  done
  [ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
  [ -z "$client_pid" ] || kill "$client_pid" 2>/dev/null || true
  sleep 1
  ip netns del sb-lab-client 2>/dev/null || true
  ip netns del sb-lab-server 2>/dev/null || true
}
trap cleanup EXIT INT TERM
modprobe veth
mkdir -p /var/run/netns
for role in server client; do
  root="$LAB/$role"
  mkdir -p "$root/lib" "$root/usr/lib" "$root/etc/swanctl" "$root/var/run" "$root/dev"
  for package in "$BASE/sdk/build_dir/target-x86_64_musl/strongswan-6.1.0/.pkgdir/"strongswan*; do
    [ ! -d "$package" ] || cp -a "$package/." "$root/"
  done
  cp -L /lib/libc.so "$root/lib/libc.so"
  cp -L /lib/ld-musl-x86_64.so.1 "$root/lib/ld-musl-x86_64.so.1"
  cp -L /lib/libgcc_s.so.1 "$root/lib/libgcc_s.so.1"
  cp -L /usr/lib/libgmp.so.10 "$root/usr/lib/libgmp.so.10"
  cp "$BASE/lab/strongswan.conf" "$root/etc/strongswan.conf"
  cp "$BASE/lab/$role.conf" "$root/etc/swanctl/swanctl.conf"
  chmod 600 "$root/etc/swanctl/swanctl.conf"
  for spec in 'null 1 3' 'random 1 8' 'urandom 1 9'; do
    set -- $spec
    mknod -m 666 "$root/dev/$1" c "$2" "$3"
  done
  ip netns add "sb-lab-$role"
  ip -n "sb-lab-$role" link set lo up
  ip -n "sb-lab-$role" link add xfrm0 type xfrm if_id 42
  ip -n "sb-lab-$role" link set xfrm0 mtu 1280 up
done
ip link add sb-lab-s type veth peer name sb-lab-c
ip link set sb-lab-s netns sb-lab-server
ip link set sb-lab-c netns sb-lab-client
ip -n sb-lab-server addr add 172.22.77.1/24 dev sb-lab-s
ip -n sb-lab-client addr add 172.22.77.2/24 dev sb-lab-c
ip -n sb-lab-server link set sb-lab-s up
ip -n sb-lab-client link set sb-lab-c up
ip netns exec sb-lab-client sysctl -w net.ipv4.conf.sb-lab-c.promote_secondaries=1
ip -n sb-lab-server addr add 10.77.0.1/32 dev xfrm0
# Keep static routes alive while the Linux client reinstalls its virtual IP on roam.
ip -n sb-lab-client addr add 198.19.77.254/32 dev xfrm0
ip -n sb-lab-server route add 10.77.0.2/32 dev xfrm0
ip -n sb-lab-client route add 10.77.0.1/32 dev xfrm0
ip netns exec sb-lab-server chroot "$LAB/server" /usr/lib/ipsec/charon > "$LAB/server.log" 2>&1 &
server_pid=$!
ip netns exec sb-lab-client chroot "$LAB/client" /usr/lib/ipsec/charon > "$LAB/client.log" 2>&1 &
client_pid=$!
swan() {
  role=$1; shift
  ip netns exec "sb-lab-$role" chroot "$LAB/$role" /usr/sbin/swanctl "$@"
}
i=0
while [ ! -S "$LAB/server/var/run/charon.vici" ] || [ ! -S "$LAB/client/var/run/charon.vici" ]; do
  i=$((i+1)); [ "$i" -lt 15 ] || { tail -15 "$LAB/server.log" "$LAB/client.log"; exit 1; }
  sleep 1
done
swan server --load-all --noprompt
swan client --load-all --noprompt
swan client --initiate --child lab-child --timeout 15
ip netns exec sb-lab-client ping -I 10.77.0.2 -c 4 -W 2 10.77.0.1 > "$LAB/ping-before.txt"
ip netns exec sb-lab-server ping -I 10.77.0.1 -c 4 -W 2 10.77.0.2 > "$LAB/ping-reverse-before.txt"
swan server --list-sas > "$LAB/sas-before.txt"
swan server --list-sas --raw > "$LAB/sas-before.raw"
ip -n sb-lab-client addr add 172.22.77.3/24 dev sb-lab-c
ip -n sb-lab-client addr del 172.22.77.2/24 dev sb-lab-c
i=0
until swan server --list-sas | grep -q '172.22.77.3'; do
  i=$((i+1)); [ "$i" -lt 30 ] || { tail -25 "$LAB/server.log" "$LAB/client.log"; exit 1; }
  sleep 1
done
sleep 1
i=0
until ip netns exec sb-lab-client ping -I 10.77.0.2 -c 4 -W 2 10.77.0.1 > "$LAB/ping-after.txt" 2>&1 && grep -q '4 packets received' "$LAB/ping-after.txt"; do
  i=$((i+1)); [ "$i" -lt 4 ] || { cat "$LAB/ping-after.txt"; exit 1; }
  sleep 1
done
ip netns exec sb-lab-server ping -I 10.77.0.1 -c 4 -W 2 10.77.0.2 > "$LAB/ping-reverse-after.txt"
swan server --list-sas > "$LAB/sas-after.txt"
swan server --list-sas --raw > "$LAB/sas-after.raw"
for phase in before after; do
  sed -n -e '/^lab: /p' -e '/lab-child: /p' -e 's/^    in  \([^ ]*\) .*/in \1/p' -e 's/^    out \([^ ]*\) .*/out \1/p' "$LAB/sas-$phase.txt" > "$LAB/identity-$phase.txt"
  [ "$(wc -l < "$LAB/identity-$phase.txt")" -eq 4 ]
done
cmp "$LAB/identity-before.txt" "$LAB/identity-after.txt"
cat "$LAB/ping-before.txt" "$LAB/ping-after.txt" "$LAB/ping-reverse-before.txt" "$LAB/ping-reverse-after.txt"
cat "$LAB/sas-before.txt" "$LAB/sas-after.txt"
printf 'VM PASS: PSK, bidirectional encrypted traffic, MOBIKE address migration, unchanged IKE/Child identities and SPIs.\n'
