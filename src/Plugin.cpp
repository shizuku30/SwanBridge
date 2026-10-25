#include <windows.h>
#include <winrt/Windows.ApplicationModel.Background.h>
#include <winrt/Windows.ApplicationModel.Core.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Networking.Vpn.h>
#include <winrt/Windows.Data.Xml.Dom.h>
#include <winrt/Windows.Networking.Sockets.h>
#include <winrt/Windows.Networking.Connectivity.h>
#include <winrt/Windows.Security.Cryptography.DataProtection.h>
#include <winrt/Windows.Storage.Streams.h>
#include <winrt/Windows.System.Threading.h>
#include <atomic>
#include <chrono>
#include <mutex>
#include <shared_mutex>
#include <set>
#include "Diagnostics.h"
#include "EngineContract.h"
#include "NativeEngine.h"
#include "RecoveryPolicy.h"
#include "ProfileConfiguration.h"
#include "UiResources.h"

using namespace winrt;
using namespace Windows::ApplicationModel::Background;
using namespace Windows::Networking::Vpn;
using namespace Windows::Networking;
using namespace Windows::Networking::Sockets;
using namespace Windows::Storage;
using namespace Windows::Security::Cryptography::DataProtection;

namespace swanbridge
{
    struct VpnPlugIn : implements<VpnPlugIn, IVpnPlugIn>
    {
        NativeEngine native;
        sb_engine* engine = nullptr;
        VpnChannel vpnChannel{ nullptr };
        DatagramSocket transport{ nullptr };
        Windows::Foundation::IInspectable transportContext{nullptr};
        hstring transportContextId;
        bool engineOwnsTransport = false;
        handle ready{ CreateEventW(nullptr, TRUE, FALSE, nullptr) };
        std::atomic<bool> connected{ false };
        std::atomic<bool> cleanupPending{ false };
        std::shared_mutex lifecycle;
        std::mutex diagnosticsLock;
        std::mutex sendLock;
        std::mutex receiveLock;
        std::wstring log;
        ULONGLONG lastPublish = 0;
        Windows::System::Threading::ThreadPoolTimer healthTimer{ nullptr };
        std::atomic<uint64_t> generation{ 0 }, wireTx{ 0 }, wireRx{ 0 }, dropTx{ 0 }, dropRx{ 0 };
        std::atomic<uint64_t> staleTransportRx{0};
        std::mutex faultLock;
        ULONGLONG lastFaultRead = 0;
        bool faultActive = false;
        bool mobilityEnabled = false;
        uint16_t gatewayNatPort = 4500;
        std::atomic<bool> checkingMobility{ false }, networkDirty{ false };
        ULONGLONG lastPathProbe = 0, migrationStarted = 0;
        uint32_t observedMobikeValidations = 0;
        uint32_t mobilityNetworkChanges = 0;
        bool fullTunnel = false;
        std::atomic<uint64_t> blockedIpv6{ 0 };
        std::wstring acceptedNetwork, candidateNetwork;
        hstring lastMobikeProbe;
        Windows::Networking::Connectivity::NetworkInformation::NetworkStatusChanged_revoker networkChanged;

        bool DropForAcceptance() noexcept
        {
#ifdef SWANBRIDGE_ACCEPTANCE_HOOKS
            try
            {
                std::lock_guard guard(faultLock);
                if (GetTickCount64() - lastFaultRead < 100) return faultActive;
                lastFaultRead = GetTickCount64();
                auto values = ApplicationData::Current().LocalSettings().Values();
                faultActive = false;
                if (values.HasKey(L"AcceptanceLeaseExpiresMs") && values.HasKey(L"AcceptanceDropUntilMs"))
                {
                    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    faultActive = AcceptanceDropActive(now, unbox_value<int64_t>(values.Lookup(L"AcceptanceLeaseExpiresMs")),
                        unbox_value<int64_t>(values.Lookup(L"AcceptanceDropUntilMs")));
                }
                return faultActive;
            }
            catch (...) { return false; }
#else
            return false;
#endif
        }

        struct Apartment
        {
            Apartment() { init_apartment(apartment_type::multi_threaded); }
            ~Apartment() { uninit_apartment(); }
        };

        void Publish(bool force = false) noexcept
        {
            try
            {
                std::lock_guard guard(diagnosticsLock);
                const auto now = GetTickCount64();
                if (!force && now - lastPublish < 250) return;
                lastPublish = now;
                auto values = ApplicationData::Current().LocalSettings().Values();
                values.Insert(L"ChannelUp", box_value(connected.load()));
                values.Insert(L"EngineRunning", box_value(engine != nullptr));
                values.Insert(L"HeartbeatAt", box_value(clock::now()));
                values.Insert(L"WireUdpTx", box_value(wireTx.load()));
                values.Insert(L"WireUdpRx", box_value(wireRx.load()));
                values.Insert(L"StaleTransportRx", box_value(staleTransportRx.load()));
                values.Insert(L"RouteMode", box_value(fullTunnel ? 0u : 1u));
                values.Insert(L"FullTunnelIpv6RouteRequested", box_value(fullTunnel));
                values.Insert(L"BlockedIpv6Packets", box_value(blockedIpv6.load()));
                // Persist only scalar diagnostics, never a transport-owned COM object.
                if (!transportContextId.empty()) values.Insert(L"ActiveTransportContext", box_value(transportContextId));
                values.Insert(L"FaultDropTx", box_value(dropTx.load()));
                values.Insert(L"FaultDropRx", box_value(dropRx.load()));
#ifdef SWANBRIDGE_ACCEPTANCE_HOOKS
                values.Insert(L"AcceptanceHooksEnabled", box_value(true));
#else
                values.Insert(L"AcceptanceHooksEnabled", box_value(false));
#endif
                if (!engine)
                {
                    values.Insert(L"UnderlayInterfaceIndex", box_value(0u));
                    values.Insert(L"TransportInterfacePinned", box_value(false));
                    values.Insert(L"Authenticated", box_value(false));
                    values.Insert(L"ChildSaUp", box_value(false));
                    values.Insert(L"MobikeEnabled", box_value(false));
                    values.Insert(L"MobikeNegotiated", box_value(false));
                    values.Insert(L"MobikePending", box_value(false));
                    return;
                }
                sb_status state{};
                state.size = sizeof(state);
                sb_mobike_status mobility{}; mobility.size = sizeof(mobility);
                sb_rekey_status rekey{}; rekey.size = sizeof(rekey);
                native.lifecycleStatus(engine, &state, &mobility, &rekey);
                values.Insert(L"TransportOwner", box_value(engineOwnsTransport ? L"NativeEngine" : L"WindowsVpnFramework"));
                values.Insert(L"PacketFaultInjectionSupported", box_value(!engineOwnsTransport));
                const auto underlay = native.underlayInterface(engine);
                values.Insert(L"UnderlayInterfaceIndex", box_value(underlay));
                values.Insert(L"TransportInterfacePinned", box_value(underlay != 0));
                if (engineOwnsTransport) {
                    values.Insert(L"WireUdpTx", box_value(state.ike_tx + state.esp_tx));
                    values.Insert(L"WireUdpRx", box_value(state.ike_rx + state.esp_rx));
                }
                values.Insert(L"Authenticated", box_value(state.authenticated != 0));
                values.Insert(L"ChildSaUp", box_value(state.child_up != 0));
                values.Insert(L"VirtualIPv4", box_value(to_hstring(state.virtual_address)));
                values.Insert(L"ServerIPv4", box_value(to_hstring(state.server_address)));
                values.Insert(L"IkeTx", box_value(state.ike_tx));
                values.Insert(L"IkeRx", box_value(state.ike_rx));
                values.Insert(L"EspTx", box_value(state.esp_tx));
                values.Insert(L"EspRx", box_value(state.esp_rx));
                values.Insert(L"PlainTx", box_value(state.plain_tx));
                values.Insert(L"PlainRx", box_value(state.plain_rx));
                values.Insert(L"LocalIPv4", box_value(to_hstring(state.local_address)));
                values.Insert(L"LocalUdpPort", box_value(state.local_port));
                values.Insert(L"IkeUniqueId", box_value(state.ike_id));
                values.Insert(L"ChildSpiIn", box_value(state.spi_in));
                values.Insert(L"ChildSpiOut", box_value(state.spi_out));
                values.Insert(L"IkeRekeysCompleted", box_value(rekey.ike_completed));
                values.Insert(L"ChildRekeysCompleted", box_value(rekey.child_completed));
                values.Insert(L"ChildUniqueId", box_value(rekey.child_id));
                values.Insert(L"IkeEstablishments", box_value(rekey.ike_establishments));
                values.Insert(L"ChildEstablishments", box_value(rekey.child_establishments));
                values.Insert(L"MobikeEnabled", box_value(mobility.enabled != 0));
                values.Insert(L"MobikeNegotiated", box_value(mobility.negotiated != 0));
                values.Insert(L"MobikePending", box_value(mobility.pending != 0));
                values.Insert(L"MobikeAttempts", box_value(mobility.attempts));
                values.Insert(L"MobikeCompleted", box_value(mobility.completed));
                values.Insert(L"MobikeProbesCompleted", box_value(mobility.probes_completed));
                values.Insert(L"MobikeUpdatesSent", box_value(mobility.updates_sent));
                values.Insert(L"MobikeUpdatesAcked", box_value(mobility.updates_acked));
                values.Insert(L"MobikeSaUpdates", box_value(mobility.sa_updates));
                values.Insert(L"MobikeError", box_value(mobility.last_error));
                values.Insert(L"MobikeNetworkChanges", box_value(mobilityNetworkChanges));
                values.Insert(L"IkeSpiInitiator", box_value(mobility.ike_spi_i));
                values.Insert(L"IkeSpiResponder", box_value(mobility.ike_spi_r));
                values.Insert(L"MobikeVerifiedLocalIPv4", box_value(to_hstring(mobility.verified_local)));
            }
            catch (...) {}
        }

        static void Log(void* context, char const* message) noexcept
        {
            try
            {
                Apartment apartment;
                auto self = static_cast<VpnPlugIn*>(context);
                const auto line = to_hstring(message);
                std::lock_guard guard(self->diagnosticsLock);
                self->log.append(line).append(L"\n");
                if (self->log.size() > 3000) self->log.erase(0, self->log.size() - 2800);
                ApplicationData::Current().LocalSettings().Values().Insert(L"EngineLog", box_value(self->log));
            }
            catch (...) {}
        }

        static int Send(void* context, uint8_t const* bytes, uint32_t length) noexcept
        {
            auto self = static_cast<VpnPlugIn*>(context);
            if (WaitForSingleObject(self->ready.get(), 5000) != WAIT_OBJECT_0 || !self->connected) return 0;
            try
            {
                Apartment apartment;
                if (self->DropForAcceptance()) { ++self->dropTx; self->Publish(); return 1; }
                std::lock_guard guard(self->sendLock);
                VpnPacketBuffer packet{ nullptr };
                self->vpnChannel.RequestVpnPacketBuffer(VpnDataPathType::Send, packet);
                if (self->transportContext) packet.TransportContext(self->transportContext);
                auto buffer = packet.Buffer();
                if (length > buffer.Capacity()) throw hresult_invalid_argument(L"ESP datagram exceeds channel capacity");
                memcpy(buffer.data(), bytes, length);
                buffer.Length(length);
                self->vpnChannel.AppendVpnSendPacketBuffer(packet);
                self->vpnChannel.FlushVpnSendPacketBuffers();
                ++self->wireTx;
                self->Publish();
                return 1;
            }
            catch (...) { RecordEvent(L"Transport.SendFailed", L"SB2005"); return 0; }
        }

        static void Receive(void* context, uint8_t const* bytes, uint32_t length) noexcept
        {
            auto self = static_cast<VpnPlugIn*>(context);
            if (!self->connected) return;
            try
            {
                Apartment apartment;
                std::lock_guard guard(self->receiveLock);
                VpnPacketBuffer packet{ nullptr };
                self->vpnChannel.RequestVpnPacketBuffer(VpnDataPathType::Receive, packet);
                auto buffer = packet.Buffer();
                if (length > buffer.Capacity()) throw hresult_invalid_argument(L"IP packet exceeds channel capacity");
                memcpy(buffer.data(), bytes, length);
                buffer.Length(length);
                self->vpnChannel.AppendVpnReceivePacketBuffer(packet);
                self->vpnChannel.FlushVpnReceivePacketBuffers();
                self->Publish();
            }
            catch (...) { RecordEvent(L"Transport.ReceiveFailed", L"SB2006"); }
        }

        void StopEngine() noexcept
        {
            connected = false;
            networkChanged.revoke();
            mobilityEnabled = false; lastPathProbe = 0; migrationStarted = 0;
            acceptedNetwork.clear(); candidateNetwork.clear();
            ++generation;
            if (healthTimer) { healthTimer.Cancel(); healthTimer = nullptr; }
            SetEvent(ready.get());
            if (transport) { try { transport.Close(); } catch (...) {} transport = nullptr; }
            if (engine)
            {
                Publish(true);
                native.stop(engine);
                engine = nullptr;
            }
            transportContext = nullptr;
            transportContextId.clear();
            engineOwnsTransport = false;
            Publish(true);
        }

        ~VpnPlugIn() { StopEngine(); }

        static std::wstring NetworkFingerprint(std::wstring_view physicalAddress) noexcept
        {
            try
            {
            using Windows::Networking::Connectivity::NetworkInformation;
            std::set<std::wstring> adapters, parts;
            const auto hosts = NetworkInformation::GetHostNames();
            for (auto const& host : hosts)
                if (host.CanonicalName() == physicalAddress && host.IPInformation() && host.IPInformation().NetworkAdapter())
                    adapters.insert(std::wstring(to_hstring(host.IPInformation().NetworkAdapter().NetworkAdapterId())));
            for (auto const& id : adapters) parts.insert(id);
            for (auto const& profile : NetworkInformation::GetConnectionProfiles())
                if (const auto adapter = profile.NetworkAdapter())
                {
                    const auto id = std::wstring(to_hstring(adapter.NetworkAdapterId()));
                    if (adapters.contains(id)) parts.insert(id + L":" + std::wstring(profile.ProfileName()));
                }
            std::wstring fingerprint;
            for (auto const& part : parts) fingerprint.append(part).append(L";");
            return fingerprint;
            }
            catch (...) { return {}; } // Optional profile metadata must not tear down an authenticated tunnel.
        }

        static hstring NewTransportContextId()
        {
            guid id; check_hresult(CoCreateGuid(reinterpret_cast<GUID*>(&id)));
            return to_hstring(id);
        }

        bool ConsumeMobikeProbe()
        {
#ifdef SWANBRIDGE_ACCEPTANCE_HOOKS
            const auto values = ApplicationData::Current().LocalSettings().Values();
            if (values.HasKey(L"AcceptanceMobikeProbeToken") && values.HasKey(L"AcceptanceMobikeProbeExpiresMs"))
            {
                const auto token = unbox_value<hstring>(values.Lookup(L"AcceptanceMobikeProbeToken"));
                const auto expiry = unbox_value<int64_t>(values.Lookup(L"AcceptanceMobikeProbeExpiresMs"));
                const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                if (token != lastMobikeProbe && expiry > now && expiry - now <= 60000)
                { lastMobikeProbe = token; values.Insert(L"MobikeProbeConsumed", box_value(token)); return true; }
            }
#endif
            return false;
        }

        bool CheckMobility(uint64_t expectedGeneration) noexcept
        {
            if (checkingMobility.exchange(true)) return true;
            struct Release { std::atomic<bool>& flag; ~Release() { flag = false; } } release{checkingMobility};
            try
            {
                sb_status state{}; state.size = sizeof(state);
                sb_mobike_status mobility{}; mobility.size = sizeof(mobility);
                sb_path path{}; path.size = sizeof(path);
                std::wstring fingerprint;
                {
                    std::unique_lock guard(lifecycle);
                    if (!connected || generation != expectedGeneration || !engine || !mobilityEnabled) return true;
                    const auto now = GetTickCount64();
                    if (now - lastPathProbe < 1000 && !networkDirty.exchange(false)) return true;
                    lastPathProbe = now;
                    native.status(engine, &state); native.mobility(engine, &mobility);
                    if (!state.authenticated || !state.child_up || !mobility.negotiated) return true;
                    if (mobility.last_error) return false;
                    if (mobility.pending)
                    {
                        if (!migrationStarted) migrationStarted = now;
                        return now - migrationStarted < 45000;
                    }
                    if (native.probePath(engine, &path)) return true;
                    fingerprint = NetworkFingerprint(to_hstring(path.local_address).c_str());
                    if (mobility.completed + mobility.probes_completed != observedMobikeValidations)
                    {
                        observedMobikeValidations = mobility.completed + mobility.probes_completed;
                        acceptedNetwork = candidateNetwork.empty() ? fingerprint : candidateNetwork;
                        candidateNetwork.clear(); migrationStarted = 0;
                        ApplicationData::Current().LocalSettings().Values().Insert(L"MobikeValidatedAt", box_value(clock::now()));
                        RecordEvent(L"Mobike.Validated");
                    }
                    const auto changed = strcmp(path.local_address, state.local_address) != 0 ||
                        (!fingerprint.empty() && fingerprint != acceptedNetwork);
                    if (!changed && !ConsumeMobikeProbe()) return true;
                    if (changed) ++mobilityNetworkChanges;
                    candidateNetwork = fingerprint; migrationStarted = now;
                }
                RecordEvent(L"Mobike.RebindingUdp");
                {
                    std::unique_lock guard(lifecycle);
                    if (!connected || generation != expectedGeneration || !engine) return true;
                    // Replacing the framework socket triggers a Windows redial, so migrate only the native wire socket.
                    SetMobikeStage(L"RebindNativeUdp");
                    const auto result = native.rebindUdp(engine, path.local_address, &path);
                    if (result && result != 3) throw hresult_error(E_FAIL, L"MOBIKE path update was rejected by the engine");
                    Publish(true); RecordEvent(L"Mobike.UpdateQueued");
                    SetMobikeStage(L"UpdateQueued");
                }
                return true;
            }
            catch (hresult_error const& error)
            {
                SetEvent(ready.get());
                if (generation != expectedGeneration) return true;
                try {
                    const auto values = ApplicationData::Current().LocalSettings().Values();
                    values.Insert(L"MobikeFailure", box_value(error.message()));
                    values.Insert(L"MobikeFailureHresult", box_value(static_cast<int32_t>(error.code())));
                    values.Insert(L"LastMobikeTransportFailure", box_value(error.message()));
                    values.Insert(L"LastMobikeTransportFailureHresult", box_value(static_cast<int32_t>(error.code())));
                    if (values.HasKey(L"MobikeTransportStage")) values.Insert(L"LastMobikeTransportFailureStage", values.Lookup(L"MobikeTransportStage"));
                } catch (...) {}
                RecordEvent(L"Mobike.TransportFailed", L"SB3101"); return false;
            }
            catch (...) { SetEvent(ready.get()); if (generation != expectedGeneration) return true; RecordEvent(L"Mobike.TransportFailed", L"SB3101"); return false; }
        }

        static void SetMobikeStage(wchar_t const* stage) noexcept
        {
            try { ApplicationData::Current().LocalSettings().Values().Insert(L"MobikeTransportStage", box_value(stage)); } catch (...) {}
        }

        void CheckHealth(uint64_t expectedGeneration) noexcept
        {
            try
            {
                Apartment apartment;
                const bool mobilityFailed = !CheckMobility(expectedGeneration);
                bool lost = false;
                {
                    std::shared_lock guard(lifecycle);
                    if (!connected || generation != expectedGeneration || !engine) return;
                    sb_status state{}; state.size = sizeof(state);
                    native.status(engine, &state);
                    lost = !state.authenticated || !state.child_up || mobilityFailed;
                    Publish(true);
                }
                if (!lost) return;
                {
                    std::unique_lock guard(lifecycle);
                    if (!connected || generation != expectedGeneration) return;
                    connected = false;
                    SetEvent(ready.get());
                }
                RecordEvent(mobilityFailed ? L"Mobike.Failed" : L"Connection.SaLost", mobilityFailed ? L"SB3101" : L"SB3001");
                const auto values = ApplicationData::Current().LocalSettings().Values();
                values.Insert(L"LastSaLossAt", box_value(clock::now()));
                {
                    std::lock_guard guard(diagnosticsLock);
                    values.Insert(L"LastSaLossLog", box_value(log));
                }
                // Stop outside the lifecycle lock: Windows may issue Disconnect.
                try { vpnChannel.SetErrorMessage(LocalizedProviderError(mobilityFailed ? L"SB3101: MOBIKE migration failed; reconnect is required." :
                    L"SB3001: IKE or Child SA expired; reconnect is required.")); } catch (...) {}
                try { vpnChannel.Stop(); } catch (...) { RecordEvent(L"Connection.StopFailed", L"SB3002"); }
                cleanupPending = true;
                CompletePendingCleanup();
            }
            catch (...) { RecordEvent(L"Connection.HealthFailed", L"SB3002"); }
        }

        void Connect(VpnChannel const& channel)
        {
            std::unique_lock guard(lifecycle);
            cleanupPending = false;
            StopEngine();
            vpnChannel = channel;
            ResetEvent(ready.get());
            RecordEvent(L"Connect");
            const auto values = ApplicationData::Current().LocalSettings().Values();
            values.Insert(L"LastError", box_value(L""));
            values.Insert(L"EngineLog", box_value(L""));
            if (values.HasKey(L"FailureDetail")) values.Remove(L"FailureDetail");
            if (values.HasKey(L"FailureHresult")) values.Remove(L"FailureHresult");
            for (auto const* key : {L"MobikeFailure",L"MobikeFailureHresult",L"MobikeTransportStage"})
                if (values.HasKey(key)) values.Remove(key);
            log.clear();
            wireTx = 0; wireRx = 0; dropTx = 0; dropRx = 0; staleTransportRx = 0;
            Windows::Storage::Streams::IBuffer plaintext{ nullptr };
            try
            {
                values.Insert(L"ConnectStage", box_value(L"ProfileAndCredentials"));
                const auto settings = ParseProfile(channel.Configuration().CustomField());
                const auto& options = settings.options;
                fullTunnel = options.routeMode == 0;
                blockedIpv6 = 0;
                const auto reference = settings.credentialReference;
                const auto folder = ApplicationData::Current().LocalFolder().GetFolderAsync(L"Credentials").get();
                const auto file = folder.GetFileAsync(reference + L".bin").get();
                plaintext = DataProtectionProvider().UnprotectAsync(FileIO::ReadBufferAsync(file).get()).get();
                if (!plaintext.Length() || plaintext.Length() > 1024) throw hresult_invalid_argument(InvalidConfiguration);
                native.Load();
                transport = DatagramSocket();
                if (options.mobike)
                {
                    transportContextId = NewTransportContextId();
                    transportContext = box_value(transportContextId);
                    channel.AddAndAssociateTransport(transport, transportContext);
                }
                else channel.AssociateTransport(transport, nullptr);
                const auto server = to_string(options.server), local = to_string(options.localId), remote = to_string(options.remoteId);
                sb_config config{};
                config.size = sizeof(config);
                config.server = server.c_str(); config.local_id = local.c_str(); config.remote_id = remote.c_str();
                config.psk = plaintext.data(); config.psk_length = plaintext.Length();
                config.timeout_ms = options.connectTimeout * 1000; config.log = Log; config.context = this;
                const auto policy = NativePolicy(options);
                const auto rekey = NativeRekeyPolicy(options);
                values.Insert(L"ConnectStage", box_value(L"StartEngine"));
                RecordEvent(L"Ike.Starting");
                const int result = native.startLifecycle(&config, &policy, &rekey, options.mobike, &engine);
                SecureZeroMemory(plaintext.data(), plaintext.Length());
                plaintext = nullptr;
                if (result == 1) throw hresult_error(E_FAIL, L"SB2007: Native engine initialization failed before IKE authentication. See EngineLog.");
                if (result) throw hresult_error(E_FAIL, L"SB2002: PSK authentication or Child SA establishment failed. See EngineLog.");
                sb_status state{}; state.size = sizeof(state);
                native.status(engine, &state);
                if (!state.authenticated || !state.child_up || !state.virtual_address[0])
                    throw hresult_error(E_FAIL, L"SB2002: No authenticated IPv4 Child SA.");
                RecordEvent(L"Ike.ChildSaUp");
                engineOwnsTransport = options.mobike;
                if (engineOwnsTransport) {
                    if (native.attachIpReceiver(engine, Receive, this)) throw hresult_error(E_FAIL, L"SB2003: Could not attach the Windows L3 receiver.");
                } else if (native.handoff(engine, Send, Receive, this))
                    throw hresult_error(E_FAIL, L"SB2003: Could not transfer the UDP transport.");
                // The framework socket keeps the UWP channel alive; MOBIKE's wire socket stays in the engine.
                values.Insert(L"ConnectStage", box_value(L"BindFrameworkTransport"));
                if (engineOwnsTransport) transport.BindServiceNameAsync(L"0").get();
                else transport.BindEndpointAsync(HostName(to_hstring(state.local_address)), to_hstring(state.local_port)).get();
                transport.ConnectAsync(HostName(to_hstring(state.server_address)), to_hstring(options.natPort)).get();
                const auto dns = single_threaded_vector<HostName>();
                if (options.dnsMode == 0)
                    for (uint32_t i = 0; i < state.dns_count; ++i) dns.Append(HostName(to_hstring(state.dns[i])));
                else if (options.dnsMode == 1)
                    for (auto const& dnsServer : Tokens(options.customDns)) dns.Append(HostName(dnsServer));
                VpnRouteAssignment routes;
                values.Insert(L"ConnectStage", box_value(L"BuildRouteAssignment"));
                const auto included = single_threaded_vector<VpnRoute>();
                {
                    std::set<std::wstring> added;
                    const std::wstring routeText = fullTunnel ? std::wstring(FullTunnelIpv4Routes) : options.splitRoutes;
                    for (auto const& route : Tokens(routeText))
                    {
                        std::wstring address; std::uint8_t prefix;
                        if (!ParseRoute(route, address, prefix)) throw hresult_invalid_argument(InvalidConfiguration);
                        if (added.insert(address + L"/" + std::to_wstring(prefix)).second)
                            included.Append(VpnRoute(HostName(address), prefix));
                    }
                    // Keep configured DNS traffic inside the tunnel even with split routes.
                    for (auto const& dnsServer : dns)
                        if (added.insert(std::wstring(dnsServer.CanonicalName()) + L"/32").second)
                            included.Append(VpnRoute(dnsServer, 32));
                }
                const auto excluded = single_threaded_vector<VpnRoute>();
                excluded.Append(VpnRoute(HostName(to_hstring(state.server_address)), 32));
                routes.Ipv4InclusionRoutes(included);
                routes.Ipv4ExclusionRoutes(excluded);
                const auto included6 = single_threaded_vector<VpnRoute>();
                if (fullTunnel)
                {
                    included6.Append(VpnRoute(HostName(L"::"), 1));
                    included6.Append(VpnRoute(HostName(L"8000::"), 1));
                }
                routes.Ipv6InclusionRoutes(included6);
                routes.Ipv6ExclusionRoutes(single_threaded_vector<VpnRoute>());
                routes.ExcludeLocalSubnets(options.excludeLocalSubnets);
                VpnNamespaceAssignment names;
                const auto namespaces = single_threaded_vector<VpnNamespaceInfo>();
                if (dns.Size()) namespaces.Append(VpnNamespaceInfo(L".", dns, nullptr));
                names.NamespaceList(namespaces);
                const auto addresses = single_threaded_vector<HostName>();
                addresses.Append(HostName(to_hstring(state.virtual_address)));
                const auto ipv6Sink = single_threaded_vector<HostName>();
                if (fullTunnel) ipv6Sink.Append(HostName(Ipv6GuardAddress));
                RecordEvent(L"Channel.Starting");
                values.Insert(L"ConnectStage", box_value(L"StartWindowsChannel"));
                // Windows sees an interface only after mutual authentication and SA installation.
                if (options.mobike)
                {
                    VpnDomainNameAssignment domains;
                    if (dns.Size()) domains.DomainNameList().Append(VpnDomainNameInfo(L".", VpnDomainNameType::Suffix, dns, nullptr));
                    if (fullTunnel) channel.StartExistingTransports(addresses.GetView(), ipv6Sink.GetView(), nullptr, routes, domains, options.mtu, 1500, false);
                    else channel.StartExistingTransports(addresses.GetView(), nullptr, nullptr, routes, domains, options.mtu, 1500, false);
                }
                else if (fullTunnel) channel.Start(addresses.GetView(), ipv6Sink.GetView(), nullptr, routes, names, options.mtu, 1500, false, transport, nullptr);
                else channel.Start(addresses.GetView(), nullptr, nullptr, routes, names, options.mtu, 1500, false, transport, nullptr);
                mobilityEnabled = options.mobike; gatewayNatPort = options.natPort;
                observedMobikeValidations = 0; mobilityNetworkChanges = 0;
                acceptedNetwork = NetworkFingerprint(to_hstring(state.local_address).c_str());
                connected = true;
                SetEvent(ready.get());
                guid session;
                check_hresult(CoCreateGuid(reinterpret_cast<GUID*>(&session)));
                values.Insert(L"SessionId", box_value(to_hstring(session)));
                values.Insert(L"ConnectedAt", box_value(clock::now()));
                const auto expectedGeneration = generation.load();
                if (mobilityEnabled)
                    networkChanged = Windows::Networking::Connectivity::NetworkInformation::NetworkStatusChanged(auto_revoke,
                        [weak = get_weak()](auto const&) { if (auto self = weak.get()) self->networkDirty = true; });
                healthTimer = Windows::System::Threading::ThreadPoolTimer::CreatePeriodicTimer(
                    [weak = get_weak(), expectedGeneration](auto const&)
                    { if (auto self = weak.get()) self->CheckHealth(expectedGeneration); }, std::chrono::seconds(1));
                Publish(true);
                RecordEvent(L"Connected");
                values.Insert(L"ConnectStage", box_value(L"Connected"));
            }
            catch (hresult_error const& error)
            {
                if (plaintext) SecureZeroMemory(plaintext.data(), plaintext.Length());
                values.Insert(L"FailureDetail", box_value(error.message()));
                values.Insert(L"FailureHresult", box_value(static_cast<int32_t>(error.code())));
                RecordEvent(L"Connect.Failed", L"SB2001");
                StopEngine();
                channel.TerminateConnection(LocalizedProviderError(error.message()));
            }
            catch (std::exception const& error)
            {
                if (plaintext) SecureZeroMemory(plaintext.data(), plaintext.Length());
                values.Insert(L"FailureDetail", box_value(to_hstring(error.what())));
                RecordEvent(L"Connect.Failed", L"SB2004");
                StopEngine();
                channel.TerminateConnection(LocalizedProviderError(L"SB2004: VPN setup failed. See ConnectStage and FailureDetail."));
            }
            catch (...)
            {
                if (plaintext) SecureZeroMemory(plaintext.data(), plaintext.Length());
                RecordEvent(L"Connect.Failed", L"SB2004");
                StopEngine();
                channel.TerminateConnection(LocalizedProviderError(L"SB2004: VPN engine failed; no tunnel was accepted."));
            }
        }

        void Disconnect(VpnChannel const& channel)
        {
            std::unique_lock guard(lifecycle);
            connected = false;
            SetEvent(ready.get());
            channel.Stop();
            cleanupPending = true;
            RecordEvent(L"Disconnect.ChannelStopped");
        }

        void CompletePendingCleanup()
        {
            if (!cleanupPending.load()) return;
            std::unique_lock guard(lifecycle);
            if (!cleanupPending.exchange(false)) return;
            StopEngine();
            RecordEvent(L"Disconnect");
        }

        void GetKeepAlivePayload(VpnChannel const& channel, VpnPacketBuffer& packet)
        {
            packet = nullptr;
            std::shared_lock guard(lifecycle);
            if (!connected || engineOwnsTransport || DropForAcceptance()) return;
            channel.RequestVpnPacketBuffer(VpnDataPathType::Send, packet);
            if (transportContext) packet.TransportContext(transportContext);
            packet.Buffer().data()[0] = 0xff;
            packet.Buffer().Length(1);
        }

        void Encapsulate(VpnChannel const&, VpnPacketBufferList const& packets, VpnPacketBufferList const&)
        {
            std::shared_lock guard(lifecycle);
            const auto count = packets.Size();
            for (uint32_t i = 0; i < count; ++i)
            {
                auto packet = packets.RemoveAtBegin();
                // Return the original L3 buffer to the input list for platform
                // cleanup. ESP output uses separate asynchronous buffers.
                packets.Append(packet);
                const auto buffer = packet.Buffer();
                if (buffer.Length() && (buffer.data()[0] >> 4) == 6)
                {
                    ++blockedIpv6;
                    Publish();
                    continue;
                }
                if (connected && engine) native.send(engine, buffer.data(), buffer.Length());
            }
        }

        void Decapsulate(VpnChannel const&, VpnPacketBuffer const& packet,
            VpnPacketBufferList const&, VpnPacketBufferList const&)
        {
            std::shared_lock guard(lifecycle);
            if (engineOwnsTransport) return;
            if (engine)
            {
                if (transportContext)
                {
                    const auto context = packet.TransportContext();
                    if (!context || unbox_value<hstring>(context) != transportContextId)
                    { ++staleTransportRx; return; }
                }
                if (DropForAcceptance()) { ++dropRx; Publish(); return; }
                const auto buffer = packet.Buffer();
                ++wireRx;
                native.feed(engine, buffer.data(), buffer.Length());
            }
        }
    };

    struct BackgroundTask : implements<BackgroundTask, IBackgroundTask>
    {
        void Run(IBackgroundTaskInstance const& instance)
        {
            const auto deferral = instance.GetDeferral();
            try
            {
                RecordEvent(L"BackgroundTask.Run");
                const auto properties = Windows::ApplicationModel::Core::CoreApplication::Properties();
                IVpnPlugIn plugin{ nullptr };
                if (properties.HasKey(PluginClass)) plugin = properties.Lookup(PluginClass).as<IVpnPlugIn>();
                else
                {
                    plugin = make<VpnPlugIn>();
                    if (properties.Insert(PluginClass, plugin)) throw hresult_error(E_UNEXPECTED);
                }
                VpnChannel::ProcessEventAsync(plugin, instance.TriggerDetails());
                // Finish native workers after the Windows channel callout has returned.
                get_self<VpnPlugIn>(plugin)->CompletePendingCleanup();
            }
            catch (hresult_error const&)
            {
                RecordEvent(L"BackgroundTask.Error", L"SB1003");
            }
            catch (...)
            {
                RecordEvent(L"BackgroundTask.Error", L"SB1004");
            }
            deferral.Complete();
        }
    };

    template <typename T>
    struct Factory : implements<Factory<T>, Windows::Foundation::IActivationFactory>
    {
        Windows::Foundation::IInspectable ActivateInstance() const { return make<T>(); }
    };
}

extern "C" HRESULT __stdcall DllGetActivationFactory(void* classId, void** factory) noexcept
{
    if (!factory) return E_POINTER;
    *factory = nullptr;
    try
    {
        hstring name;
        copy_from_abi(name, classId);
        if (name == swanbridge::BackgroundClass)
        {
            *factory = detach_abi(make<swanbridge::Factory<swanbridge::BackgroundTask>>());
            return S_OK;
        }
        if (name == swanbridge::PluginClass)
        {
            *factory = detach_abi(make<swanbridge::Factory<swanbridge::VpnPlugIn>>());
            return S_OK;
        }
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    catch (...) { return to_hresult(); }
}

extern "C" HRESULT __stdcall DllCanUnloadNow()
{
    return get_module_lock() ? S_FALSE : S_OK;
}
