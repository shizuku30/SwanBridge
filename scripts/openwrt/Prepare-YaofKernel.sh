#!/bin/bash
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")"
base=$PWD
mkdir -p kernel-build/openwrt kernel-build/yaof
tar xzf openwrt-base-64900e75.tar.gz --strip-components=1 -C kernel-build/openwrt
tar xzf yaof-91b2b72f-source.tar.gz -C kernel-build/yaof
owrt=$base/kernel-build/openwrt
yaof=$base/kernel-build/yaof
for mapping in 'bbr3 backport' 'others pending' 'arm hack' 'lrng hack' 'wg hack' 'bcmfullcone hack' 'btf hack'; do
  read -r source destination <<< "$mapping"
  cp "$yaof/PATCH/kernel/$source/"* "$owrt/target/linux/generic/$destination-6.12/"
done
mkdir -p downloads
linux=downloads/linux-6.12.112.tar.xz
test -f "$linux" || curl -fL --retry 3 -o "$linux" https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.112.tar.xz
printf '%s  %s\n' 164dc9d1f6c93c61a15e1f071c48379b467f2b17c469cce7223471968208ed03 "$linux" | sha256sum -c -
k=$base/kernel-build/linux-6.12.112
if [ -e "$k" ]; then
  test "$(readlink -f "$k")" = "$k"
  rm -rf -- "$k"
fi
tar xf "$linux" -C kernel-build
for files in "$owrt"/target/linux/generic/files "$owrt"/target/linux/x86/files; do
  [ ! -d "$files" ] || cp -a "$files/." "$k/"
done
for directory in "$owrt"/target/linux/generic/{backport,pending,hack}-6.12 "$owrt"/target/linux/x86/patches-6.12; do
  "$owrt/scripts/patch-kernel.sh" "$k" "$directory"
done
cp sdk/build_dir/target-x86_64_musl/linux-x86_64/linux-6.12.112/.config "$k/.config"
cd "$k"
scripts/config --enable KALLSYMS \
  --disable RANDOM_DEFAULT_IMPL --enable LRNG --enable LRNG_DEV_IF \
  --disable LRNG_IRQ --enable LRNG_JENT --enable LRNG_CPU --disable LRNG_SCHED \
  --enable LRNG_SELFTEST --disable LRNG_SELFTEST_PANIC --enable NETKIT \
  --enable IPV6_MULTIPLE_TABLES --disable CPU_IDLE_GOV_MENU --enable CPU_IDLE_GOV_TEO \
  --module XFRM_ALGO --module XFRM_USER --module XFRM_INTERFACE \
  --module INET_TUNNEL --module INET6_TUNNEL --module INET_AH --module INET_ESP \
  --module INET_IPCOMP --module INET_XFRM_TUNNEL --module INET6_AH \
  --module INET6_ESP --module INET6_IPCOMP --module INET6_XFRM_TUNNEL
export PATH="$base/sdk/staging_dir/toolchain-x86_64_gcc-14.3.0_musl/bin:$PATH"
export ARCH=x86 CROSS_COMPILE=x86_64-openwrt-linux-musl-
export KBUILD_BUILD_USER=builder KBUILD_BUILD_HOST=buildhost
export KBUILD_BUILD_TIMESTAMP='Sat Oct 17 21:45:38 2026' KBUILD_BUILD_VERSION=0
make olddefconfig
make -j2 modules_prepare
cp "$base/sdk/build_dir/target-x86_64_musl/linux-x86_64/linux-6.12.112/Module.symvers" .
printf 'Prepared YAOF-patched source at %s\n' "$k"
