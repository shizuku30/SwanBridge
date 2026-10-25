#!/bin/bash
set -euo pipefail
umask 022
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C
cd /work
apt-get update
apt-get install -y --no-install-recommends \
  build-essential gawk gettext git libncurses-dev libssl-dev \
  python3 python3-setuptools rsync unzip zstd file ca-certificates \
  wget curl patch bzip2 xz-utils gnupg autoconf automake libtool flex bison
apt-get clean
id builder >/dev/null 2>&1 || useradd --create-home --shell /bin/bash builder
[ "${1:-}" != --dependencies-only ] || exit 0
printf '%s  %s\n' \
  1864152619092e781fa36a401960c8e9ae42d6a364c44ee5f0b197ca5f3c0fcc \
  openwrt-sdk-25.12.6-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst | sha256sum -c -
test -d sdk || {
  mkdir sdk
  tar --zstd -xf openwrt-sdk-25.12.6-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst \
    --strip-components=1 -C sdk
}
chown -R builder:builder /work
rm -f openwrt-sdk-25.12.6-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst
printf 'SDK ready at /work/sdk\n'
