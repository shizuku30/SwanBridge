#!/bin/bash
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")"
test "$(id -u)" != 0
tar xf package-inputs.tar
mkdir -p sdk/package/strongswan/files
cp strongswan/Makefile sdk/package/strongswan/
cp -R files/. sdk/package/strongswan/files/
find sdk/package/strongswan -type f -exec sed -i 's/\r$//' {} +
patch -d sdk/package/strongswan -p1 < swanctl-permissions.patch
mkdir -p base
tar xzf openwrt-base-64900e75.tar.gz --strip-components=1 -C base \
  openwrt-64900e756efa667774214f9c6b17c113222e01f7/package
cd sdk
printf 'src-link base %s/base/package\n' "$(dirname "$PWD")" > feeds.conf
./scripts/feeds update base
./scripts/feeds install -a -p base
mkdir -p dl
cp ../strongswan-6.1.0.tar.gz dl/
bash ../Sign-Packages.sh --prepare
patch -p1 < ../sdk-sign.patch
cat > .config <<'EOF'
CONFIG_ALL=n
CONFIG_ALL_KMODS=n
CONFIG_ALL_NONSHARED=n
CONFIG_DEVEL=y
CONFIG_SIGNED_PACKAGES=y
CONFIG_AUTOREMOVE=n
CONFIG_PACKAGE_strongswan=m
CONFIG_PACKAGE_strongswan-charon=m
CONFIG_PACKAGE_strongswan-swanctl=m
CONFIG_PACKAGE_strongswan-mod-aes=m
CONFIG_PACKAGE_strongswan-mod-attr=m
CONFIG_PACKAGE_strongswan-mod-gcm=m
CONFIG_PACKAGE_strongswan-mod-gmp=m
CONFIG_PACKAGE_strongswan-mod-hmac=m
CONFIG_PACKAGE_strongswan-mod-kdf=m
CONFIG_PACKAGE_strongswan-mod-kernel-netlink=m
CONFIG_PACKAGE_strongswan-mod-random=m
CONFIG_PACKAGE_strongswan-mod-sha1=m
CONFIG_PACKAGE_strongswan-mod-sha2=m
CONFIG_PACKAGE_strongswan-mod-socket-default=m
CONFIG_PACKAGE_strongswan-mod-vici=m
CONFIG_PACKAGE_strongswan-mod-xcbc=m
EOF
make defconfig
grep '^CONFIG_PACKAGE_strongswan' .config
bash ../Run-Guarded.sh make -j1 package/feeds/base/gmp/compile NO_DEPS=1 V=s
bash ../Run-Guarded.sh make -j1 package/strongswan/compile NO_DEPS=1 V=s
find bin -name 'strongswan*.apk' -print
bash ../Sign-Packages.sh
