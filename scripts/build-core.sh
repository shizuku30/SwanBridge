#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
source_dir="$root/third_party/strongswan-6.1.0"
build_dir="$root/build/strongswan-core/x64-mingw"
test -f "$source_dir/configure"
mkdir -p "$build_dir"
cd "$build_dir"
export PATH="/mingw64/bin:/usr/bin:$PATH"
export MAKE="$(command -v make)"
export LD="$(command -v ld)"
export PYTHON="$(command -v python3 || command -v python || true)"
if [[ -z "$PYTHON" ]]; then
    printf 'Python is required. Run scripts/Initialize-Toolchain.ps1 -InstallPackages.\n' >&2
    exit 1
fi
source_relative='../../../third_party/strongswan-6.1.0'
core_cflags='-O2 -g -std=gnu11 -Wno-pointer-sign -Wno-format'
configure_args=(
    --host=x86_64-w64-mingw32
    "--prefix=$build_dir/install" --disable-defaults --disable-dependency-tracking
    --enable-static --disable-shared --enable-monolithic
    --enable-ikev2 --enable-libipsec --enable-openssl
    --enable-nonce --enable-hmac --enable-sha1 --enable-sha2
    --enable-aes --enable-socket-win --enable-kernel-iph
    --enable-svc --enable-swanctl --enable-vici
    --with-strongswan-conf=strongswan.conf --with-swanctldir=swanctl
)
configure_key="$(printf '%s\n' "$source_dir" "$build_dir" "$PYTHON" "$core_cflags" "${configure_args[@]}" | sha256sum | cut -d' ' -f1)"
if [[ ! -f config.status || ! -f .swanbridge-configured || "$(<.swanbridge-configured)" != "$configure_key" ]]; then
    CFLAGS="$core_cflags" "$source_relative/configure" "${configure_args[@]}" > configure-output.log 2>&1 || {
            tail -n 60 configure-output.log
            exit 1
        }
    make -C src/libstrongswan --eval='swanbridge-constructors: ; $(PYTHON) $(srcdir)/plugins/plugin_constructors.py $(s_plugins) > $(srcdir)/plugin_constructors.c' swanbridge-constructors >> configure-output.log 2>&1
    make -C src/libcharon --eval='swanbridge-constructors: ; $(PYTHON) $(top_srcdir)/src/libstrongswan/plugins/plugin_constructors.py $(c_plugins) > $(srcdir)/plugin_constructors.c' swanbridge-constructors >> configure-output.log 2>&1
    printf '%s\n' "$configure_key" > .swanbridge-configured
fi
make -j4 > build-output.log 2>&1 || { tail -n 90 build-output.log; exit 1; }
mkdir -p ../../engine
./libtool --tag=CC --mode=link gcc -O2 -g -std=gnu11 -mno-ms-bitfields \
    -Wno-format -Wno-pointer-sign -include config.h \
    -I"$source_relative/src/libstrongswan" -I"$source_relative/src/libcharon" \
    ../../../src/engine/IkeProbe.c src/libcharon/libcharon.la \
    src/libstrongswan/libstrongswan.la -o ../../engine/SwanBridge.IkeProbe.exe \
    > probe-build.log 2>&1 || { tail -n 50 probe-build.log; exit 1; }
gcc -shared -O2 -g -std=gnu11 -mno-ms-bitfields -Wno-format -Wno-pointer-sign \
    -include config.h -I"$source_relative/src/libstrongswan" \
    -I"$source_relative/src/libcharon" -I"$source_relative/src/libipsec" \
    ../../../src/engine/Engine.c -Wl,--start-group src/libcharon/.libs/libcharon.a \
    src/libipsec/.libs/libipsec.a src/libstrongswan/.libs/libstrongswan.a -Wl,--end-group \
    -liphlpapi -lws2_32 -lpsapi -lcrypto -lregex \
    -Wl,--out-implib,../../engine/libSwanBridge.Engine.dll.a -o ../../engine/SwanBridge.Engine.dll \
    > engine-build.log 2>&1 || { tail -n 70 engine-build.log; exit 1; }
gcc -O2 -std=gnu11 ../../../src/engine/EngineProbe.c ../../engine/libSwanBridge.Engine.dll.a \
    -o ../../engine/SwanBridge.EngineProbe.exe
gcc -O2 -std=gnu11 ../../../src/engine/RekeyProbe.c ../../engine/libSwanBridge.Engine.dll.a \
    -o ../../engine/SwanBridge.RekeyProbe.exe
gcc -O2 -std=gnu11 -mno-ms-bitfields -Wno-format -Wno-pointer-sign \
    -include config.h -I"$source_relative/src/libstrongswan" -I"$source_relative/src/libipsec" \
    ../../../tests/IpsecMobilityTests.c -Wl,--start-group src/libipsec/.libs/libipsec.a \
    src/libstrongswan/.libs/libstrongswan.a -Wl,--end-group \
    -liphlpapi -lws2_32 -lpsapi -lcrypto -lregex -o ../../engine/IpsecMobilityTests.exe \
    > mobility-test-build.log 2>&1 || { tail -n 50 mobility-test-build.log; exit 1; }
gcc -O2 -std=gnu11 -mno-ms-bitfields -Wno-format -Wno-pointer-sign \
    -include config.h -I"$source_relative/src/libstrongswan" -I"$source_relative/src/libcharon" \
    ../../../tests/ChildSaCheckoutTests.c -Wl,--start-group src/libcharon/.libs/libcharon.a \
    src/libstrongswan/.libs/libstrongswan.a -Wl,--end-group \
    -liphlpapi -lws2_32 -lpsapi -lcrypto -lregex -o ../../engine/ChildSaCheckoutTests.exe \
    > checkout-test-build.log 2>&1 || { tail -n 50 checkout-test-build.log; exit 1; }
runtime_queue=(../../engine/SwanBridge.IkeProbe.exe ../../engine/SwanBridge.EngineProbe.exe ../../engine/SwanBridge.RekeyProbe.exe ../../engine/SwanBridge.Engine.dll ../../engine/IpsecMobilityTests.exe ../../engine/ChildSaCheckoutTests.exe)
declare -A copied_runtime=()
for ((index=0; index<${#runtime_queue[@]}; index++)); do
    while IFS= read -r runtime; do
        if [[ -z "${copied_runtime[$runtime]+present}" && -f "$root/tools/msys64/mingw64/bin/$runtime" ]]; then
            cp "$root/tools/msys64/mingw64/bin/$runtime" ../../engine/
            copied_runtime[$runtime]=1
            runtime_queue+=("../../engine/$runtime")
        fi
    done < <(objdump -p "${runtime_queue[index]}" | awk '/DLL Name:/{print $NF}' | tr -d '\r')
done
cp "$source_dir/COPYING" ../../engine/COPYING.strongswan
cp ../../../src/engine/probe.conf ../../engine/
cp ../../../src/engine/engine.conf ../../engine/
for license in openssl libsystre libtre libiconv gettext-runtime gcc libgcc winpthreads libwinpthread; do
    if [[ -d "$root/tools/msys64/mingw64/share/licenses/$license" ]]; then
        mkdir -p "../../engine/licenses/$license"
        cp -R "$root/tools/msys64/mingw64/share/licenses/$license/." "../../engine/licenses/$license/"
    fi
done
../../engine/SwanBridge.IkeProbe.exe --self-test
../../engine/IpsecMobilityTests.exe
../../engine/ChildSaCheckoutTests.exe
printf '\nstrongSwan core build completed. No IKE daemon or service was started.\n'
