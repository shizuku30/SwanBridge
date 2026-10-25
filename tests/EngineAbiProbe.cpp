#include "NativeEngine.h"
#include <iostream>
#include <stdexcept>

void Check(bool condition, char const* description)
{
    if (!condition) throw std::runtime_error(description);
    std::cout << "PASS " << description << '\n';
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2) return 2;
    try
    {
        swanbridge::NativeEngine native;
        native.module = LoadLibraryExW(argv[1], nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        Check(native.module != nullptr, "bundled native runtime loads without a toolchain PATH");
        native.Resolve(native.start, "sb_engine_start");
        native.Resolve(native.startEx, "sb_engine_start_ex");
        native.Resolve(native.startMobike, "sb_engine_start_mobike");
        native.Resolve(native.startLifecycle, "sb_engine_start_lifecycle");
        native.Resolve(native.validatePolicy, "sb_engine_validate_policy");
        native.Resolve(native.status, "sb_engine_status");
        native.Resolve(native.mobility, "sb_engine_mobike_status");
        native.Resolve(native.rekeyStatus, "sb_engine_rekey_status");
        native.Resolve(native.lifecycleStatus, "sb_engine_lifecycle_status");
        native.Resolve(native.probePath, "sb_engine_probe_path");
        native.Resolve(native.underlayInterface, "sb_engine_underlay_interface");
        native.Resolve(native.roam, "sb_engine_roam");
        native.Resolve(native.handoff, "sb_engine_handoff");
        native.Resolve(native.attachIpReceiver, "sb_engine_attach_ip_receiver");
        native.Resolve(native.rebindUdp, "sb_engine_rebind_udp");
        native.Resolve(native.feed, "sb_engine_feed_udp");
        native.Resolve(native.send, "sb_engine_send_ip");
        native.Resolve(native.stop, "sb_engine_stop");
        Check(native.start(nullptr, nullptr) == 1, "missing configuration and output rejected");
        sb_engine* engine = reinterpret_cast<sb_engine*>(1);
        Check(native.start(nullptr, &engine) == 1 && !engine, "rejected start clears the output handle");
        const uint8_t secret[] = { 1 };
        sb_config config{};
        config.server = "vpn.example.org"; config.local_id = "client"; config.remote_id = "192.0.2.1";
        config.psk = secret; config.psk_length = sizeof(secret);
        Check(native.start(&config, &engine) == 1 && !engine, "wrong C ABI version rejected before network access");
        config.size = sizeof(config);
        config.psk_length = 0;
        Check(native.start(&config, &engine) == 1 && !engine, "empty PSK rejected before network access");
        config.psk_length = 1025;
        Check(native.start(&config, &engine) == 1 && !engine, "oversized PSK rejected before network access");
        config.psk_length = 1; config.psk = nullptr;
        Check(native.start(&config, &engine) == 1 && !engine, "missing PSK bytes rejected before network access");
        auto policy = sb_policy_defaults();
        Check(native.validatePolicy(&policy) == 0, "native policy defaults accepted without network access");
        bool proposalsValid = true;
        for (auto ike : sb_ike_proposals) for (auto esp : sb_esp_proposals)
        {
            policy.ike_proposal = ike; policy.esp_proposal = esp;
            proposalsValid &= native.validatePolicy(&policy) == 0;
        }
        Check(proposalsValid, "all exposed algorithm pairs pass native whitelist validation");
        policy = sb_policy_defaults(); policy.version = 2;
        Check(native.validatePolicy(&policy) == 1, "unknown native policy version rejected");
        policy = sb_policy_defaults(); policy.size = 0;
        Check(native.validatePolicy(&policy) == 1, "wrong native policy size rejected");
        policy = sb_policy_defaults(); policy.ike_proposal = "3des-sha1-modp1024";
        Check(native.validatePolicy(&policy) == 1, "native engine cannot bypass the algorithm whitelist");
        config.psk = secret;
        engine = reinterpret_cast<sb_engine*>(1);
        Check(native.startEx(&config, &policy, &engine) == 1 && !engine,
            "invalid extended policy rejected and handle cleared before DNS or socket access");
        policy = sb_policy_defaults(); policy.local_id_type = 99;
        Check(native.validatePolicy(&policy) == 1, "unknown native identity type rejected");
        policy = sb_policy_defaults(); policy.nat_port = 65536;
        Check(native.validatePolicy(&policy) == 1, "native transport port does not truncate");
        policy = sb_policy_defaults(); policy.retransmit_timeout = 0;
        Check(native.validatePolicy(&policy) == 1 && native.validatePolicy(nullptr) == 1,
            "invalid or absent timer policy rejected");
        policy = sb_policy_defaults();
        Check(native.startMobike(&config, &policy, 2, &engine) == 1 && !engine,
            "invalid mobility switch rejected before any DNS or socket operation");
        Check(native.probePath(nullptr, nullptr) == 1 && native.roam(nullptr, "192.0.2.2", 4500) == 1,
            "inactive engines cannot probe or migrate a transport");
        Check(native.underlayInterface(nullptr) == 0, "inactive engines cannot fabricate a pinned physical interface");
        auto rekey = sb_rekey_policy_defaults();
        rekey.version = 2;
        Check(native.startLifecycle(&config, &policy, &rekey, 1, &engine) == 1 && !engine,
            "unknown rekey policy rejected before network access");
        sb_rekey_status rekeyState{}; rekeyState.size = sizeof(rekeyState);
        native.rekeyStatus(nullptr, &rekeyState);
        Check(!rekeyState.ike_completed && !rekeyState.child_completed && !rekeyState.ike_establishments,
            "inactive engines cannot fabricate rekeys or authentication events");
        Check(native.attachIpReceiver(nullptr, nullptr, nullptr) == 1 && native.rebindUdp(nullptr, "192.0.2.2", nullptr) == 1,
            "inactive engines cannot attach or rebind an owned UDP socket");
        sb_mobike_status mobility{}; mobility.size = sizeof(mobility);
        native.mobility(nullptr, &mobility);
        Check(mobility.completed == 0 && mobility.negotiated == 0,
            "inactive engine cannot fabricate a negotiated or successful MOBIKE migration");
        Check(native.send(nullptr, nullptr, 0) == 1 && native.handoff(nullptr, nullptr, nullptr, nullptr) == 1,
            "no packet injection or handoff without an authenticated engine");
        native.feed(nullptr, nullptr, 0);
        native.status(nullptr, nullptr);
        native.stop(nullptr);
        Check(true, "inactive callbacks and cleanup are safe");
        return 0;
    }
    catch (winrt::hresult_error const& error)
    {
        std::cerr << "FAIL native runtime HRESULT 0x" << std::hex << static_cast<unsigned>(error.code()) << '\n';
    }
    catch (std::exception const& error) { std::cerr << "FAIL " << error.what() << '\n'; }
    return 1;
}
