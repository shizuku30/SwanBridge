#pragma once
#include <windows.h>
#include <winrt/base.h>
#include "engine/Engine.h"

namespace swanbridge
{
    // Only C data crosses the MSVC/MinGW boundary. Load dependencies from the package.
    struct NativeEngine
    {
        HMODULE module = nullptr;
        decltype(&sb_engine_start) start = nullptr;
        decltype(&sb_engine_start_ex) startEx = nullptr;
        decltype(&sb_engine_start_mobike) startMobike = nullptr;
        decltype(&sb_engine_start_lifecycle) startLifecycle = nullptr;
        decltype(&sb_engine_validate_policy) validatePolicy = nullptr;
        decltype(&sb_engine_status) status = nullptr;
        decltype(&sb_engine_mobike_status) mobility = nullptr;
        decltype(&sb_engine_rekey_status) rekeyStatus = nullptr;
        decltype(&sb_engine_lifecycle_status) lifecycleStatus = nullptr;
        decltype(&sb_engine_probe_path) probePath = nullptr;
        decltype(&sb_engine_underlay_interface) underlayInterface = nullptr;
        decltype(&sb_engine_roam) roam = nullptr;
        decltype(&sb_engine_handoff) handoff = nullptr;
        decltype(&sb_engine_attach_ip_receiver) attachIpReceiver = nullptr;
        decltype(&sb_engine_rebind_udp) rebindUdp = nullptr;
        decltype(&sb_engine_feed_udp) feed = nullptr;
        decltype(&sb_engine_send_ip) send = nullptr;
        decltype(&sb_engine_stop) stop = nullptr;

        template <typename T> void Resolve(T& target, char const* name)
        {
            target = reinterpret_cast<T>(GetProcAddress(module, name));
            if (!target) winrt::throw_last_error();
        }

        void Load()
        {
            if (module) return;
            module = LoadPackagedLibrary(L"SwanBridge.Engine.dll", 0);
            if (!module) winrt::throw_last_error();
            try
            {
                Resolve(start, "sb_engine_start");
                Resolve(startEx, "sb_engine_start_ex");
                Resolve(startMobike, "sb_engine_start_mobike");
                Resolve(startLifecycle, "sb_engine_start_lifecycle");
                Resolve(validatePolicy, "sb_engine_validate_policy");
                Resolve(status, "sb_engine_status");
                Resolve(mobility, "sb_engine_mobike_status");
                Resolve(rekeyStatus, "sb_engine_rekey_status");
                Resolve(lifecycleStatus, "sb_engine_lifecycle_status");
                Resolve(probePath, "sb_engine_probe_path");
                Resolve(underlayInterface, "sb_engine_underlay_interface");
                Resolve(roam, "sb_engine_roam");
                Resolve(handoff, "sb_engine_handoff");
                Resolve(attachIpReceiver, "sb_engine_attach_ip_receiver");
                Resolve(rebindUdp, "sb_engine_rebind_udp");
                Resolve(feed, "sb_engine_feed_udp");
                Resolve(send, "sb_engine_send_ip");
                Resolve(stop, "sb_engine_stop");
                // The embedded runtime owns worker/TLS callbacks. Keep it, like the
                // plug-in itself, loaded until the dedicated host process exits.
                HMODULE pinned;
                if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                    reinterpret_cast<LPCWSTR>(start), &pinned)) winrt::throw_last_error();
            }
            catch (...) { FreeLibrary(module); module = nullptr; throw; }
        }

        ~NativeEngine() { if (module) FreeLibrary(module); }
        NativeEngine() = default;
        NativeEngine(NativeEngine const&) = delete;
        NativeEngine& operator=(NativeEngine const&) = delete;
    };

    static_assert(sizeof(sb_config) == 64);
    static_assert(sizeof(sb_policy) == 64);
    static_assert(offsetof(sb_status, ike_tx) == 480);
    static_assert(sizeof(sb_status) == 528);
    static_assert(sizeof(sb_mobike_status) == 144);
    static_assert(sizeof(sb_path) == 72);
    static_assert(sizeof(sb_rekey_policy) == 20 && sizeof(sb_rekey_status) == 24);
}
