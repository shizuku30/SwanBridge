#!/bin/bash
set -euo pipefail
umask 077
cd "$(dirname "$0")"
base=$PWD
modules=$base/kernel-build/modules
out=$base/yaof-packages
key=${1:?Pass a protected APK signing key path}
test -f "$key"
test ! -e "$out"
mkdir -m 755 "$out"
export PATH="$base/sdk/staging_dir/host/bin:$PATH"
kernel='kernel=6.12.112~b4125196ecec75391093e1e2edeba490-r1'
while IFS='|' read -r name autoload files deps; do
  root=$out/$name
  mkdir -p "$root/lib/modules/6.12.112" "$root/etc/modules.d" "$root/lib/apk/packages"
  for module in $files; do
    test "$(readelf -SW "$modules/$module.ko" | awk '$2 == ".gnu.linkonce.this_module" {print $6}')" = 000440
    cp "$modules/$module.ko" "$root/lib/modules/6.12.112/"
    "$base/sdk/staging_dir/toolchain-x86_64_gcc-14.3.0_musl/bin/x86_64-openwrt-linux-musl-strip" --strip-debug "$root/lib/modules/6.12.112/$module.ko"
    printf '%s\n' "$module" >> "$root/etc/modules.d/$autoload"
  done
  (cd "$root"; find . -type f | sed 's|^\.||' | sort) > "$root/lib/apk/packages/$name.list"
  apk mkpkg --sign-key "$key" \
    --info "name:$name" --info 'version:6.12.112-r2' --info 'arch:x86_64' \
    --info 'license:GPL-2.0-only' --info 'origin:swanbridge-yaof-kernel' \
    --info "description:YAOF 25.12.6 native ABI module (0x440); not for stock OpenWrt: $name" \
    --info 'url:https://github.com/QiuSimons/YAOF' \
    --info "depends:$kernel $deps" --info "provides:$name-any" \
    --files "$root" --output "$out/$name-6.12.112-r2.apk"
done <<'PACKAGES'
kmod-ipsec|30-ipsec|af_key xfrm_algo xfrm_ipcomp xfrm_user|kmod-crypto-authenc kmod-crypto-cbc kmod-crypto-deflate kmod-crypto-des kmod-crypto-echainiv kmod-crypto-hmac kmod-crypto-md5 kmod-crypto-sha1
kmod-iptunnel4|31-iptunnel4|tunnel4|
kmod-iptunnel6|31-iptunnel6|tunnel6|
kmod-ipsec4|32-ipsec4|ah4 esp4 ipcomp xfrm4_tunnel|kmod-ipsec kmod-iptunnel4
kmod-ipsec6|32-ipsec6|ah6 esp6 ipcomp6 xfrm6_tunnel|kmod-ipsec kmod-iptunnel6
kmod-xfrm-interface|xfrm-interface|xfrm_interface|kmod-ipsec4 kmod-ipsec6
PACKAGES
apk verify --keys-dir "$base/signing" "$out/"*.apk
(cd "$out"; sha256sum ./*.apk > SHA256SUMS)
