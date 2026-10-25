#!/bin/bash
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")"
base=$PWD
k=$base/kernel-build/linux-6.12.112
modules=$base/kernel-build/modules
mkdir -p "$modules"
cp kmod/Kbuild "$modules/"
cp "$k/net/key/af_key.c" "$modules/"
for name in xfrm_algo xfrm_user xfrm_ipcomp xfrm_interface_core; do
  cp "$k/net/xfrm/$name.c" "$modules/"
done
for name in tunnel4 ah4 esp4 ipcomp xfrm4_tunnel udp_tunnel_core udp_tunnel_nic; do
  cp "$k/net/ipv4/$name.c" "$modules/"
done
for name in tunnel6 ah6 esp6 ipcomp6 xfrm6_tunnel; do
  cp "$k/net/ipv6/$name.c" "$modules/"
done
export STAGING_DIR="$base/sdk/staging_dir/target-x86_64_musl"
export PATH="$base/sdk/staging_dir/toolchain-x86_64_gcc-14.3.0_musl/bin:$PATH"
export ARCH=x86 CROSS_COMPILE=x86_64-openwrt-linux-musl-
export KBUILD_BUILD_USER=builder KBUILD_BUILD_HOST=buildhost
export KBUILD_BUILD_TIMESTAMP='Sat Oct 17 21:45:38 2026' KBUILD_BUILD_VERSION=0
make -C "$k" -j2 M="$modules" KCFLAGS='-fno-caller-saves' modules
readelf -SW "$modules/xfrm_interface.ko" | grep 'this_module'
for name in udp_tunnel xfrm_interface xfrm_user esp4; do
  readelf -p .modinfo "$modules/$name.ko"
done
