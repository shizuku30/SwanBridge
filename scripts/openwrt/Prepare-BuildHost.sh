#!/bin/sh
set -eu

# Run from a dedicated staging directory on an x86_64 Linux host.
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$BASE"
test "$(id -u)" = 0
test "$(uname -m)" = x86_64
test ! -e rootfs/.prepared
test "$(df -Pk . | awk 'NR==2 {print $4}')" -gt 2800000
test "$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)" -gt 1300000
printf '%s  %s\n' \
  e77b6f10c2590cef872b33ee9f635a0e3fd1f57fb074c0e52b5c7f56147a0c86 \
  ubuntu-base-24.04.5-base-amd64.tar.gz | sha256sum -c -
umask 077
mkdir -p rootfs
tar xzpf ubuntu-base-24.04.5-base-amd64.tar.gz -C rootfs
chmod 755 rootfs
cp /etc/resolv.conf rootfs/etc/resolv.conf
printf '127.0.0.1 localhost buildhost\n' > rootfs/etc/hosts
printf '#!/bin/sh\nexit 101\n' > rootfs/usr/sbin/policy-rc.d
chmod 755 rootfs/usr/sbin/policy-rc.d
for spec in 'null 1 3' 'zero 1 5' 'random 1 8' 'urandom 1 9'; do
  set -- $spec
  test -e "rootfs/dev/$1" || mknod -m 666 "rootfs/dev/$1" c "$2" "$3"
done
mkdir -p rootfs/proc rootfs/work
mount -t proc -o ro,nosuid,nodev,noexec proc rootfs/proc
cp Build-InRoot.sh rootfs/work/
touch rootfs/.prepared
printf 'Build root prepared at %s/rootfs; no host services changed.\n' "$BASE"
