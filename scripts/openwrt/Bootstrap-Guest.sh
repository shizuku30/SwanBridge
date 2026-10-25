#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
serial=$(cat /sys/class/block/vdb/serial 2>/dev/null || cat /sys/class/block/vdb/device/serial)
test "$serial" = SB-BUILD-DATA
if [ "${1:-}" = --initialize-data ]; then
  mkfs.ext4 -L SB-BUILD-DATA /dev/vdb
fi
mkdir -p /build
grep -qs ' /build ' /proc/mounts || mount /dev/vdb /build
if [ ! -e /build/rootfs/bin/bash ]; then
  mkdir -p /build/rootfs
  tar xzpf /input/ubuntu-base-24.04.5-base-amd64.tar.gz -C /build/rootfs
fi
ip link set eth0 up
ip -4 addr replace 10.0.2.15/24 dev eth0
ip -4 route replace default via 10.0.2.2 dev eth0
printf 'nameserver 10.0.2.3\n' > /etc/resolv.conf
cp /etc/resolv.conf /build/rootfs/etc/resolv.conf
mkdir -p /etc/dropbear
cp /input/builder.pub /etc/dropbear/authorized_keys
chmod 700 /etc/dropbear
chmod 600 /etc/dropbear/authorized_keys
[ -f /etc/dropbear/dropbear_ed25519_host_key ] || \
  dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key
dropbear -R -s -g -p 22
mkdir -p /build/rootfs/proc /build/rootfs/work /build/rootfs/dev
for spec in 'null 1 3' 'zero 1 5' 'random 1 8' 'urandom 1 9'; do
  set -- $spec
  test -e "/build/rootfs/dev/$1" || mknod -m 666 "/build/rootfs/dev/$1" c "$2" "$3"
done
grep -qs ' /build/rootfs/proc ' /proc/mounts || mount -t proc -o ro,nosuid,nodev,noexec proc /build/rootfs/proc
printf '#!/bin/sh\nexit 101\n' > /build/rootfs/usr/sbin/policy-rc.d
chmod 755 /build/rootfs/usr/sbin/policy-rc.d
cp /input/Build-InRoot.sh /build/rootfs/work/
cp /input/openwrt-sdk-25.12.6-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst /build/rootfs/work/
printf 'Guest storage ready; only the SB-BUILD-DATA virtual disk was formatted.\n'
