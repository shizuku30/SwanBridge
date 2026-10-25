#include <windows.h>
#include <winrt/Windows.ApplicationModel.Background.h>
#include <winrt/Windows.Networking.Vpn.h>
#include <winrt/Windows.Storage.Streams.h>
#include <deque>
#include <iostream>
#include "EngineContract.h"

using namespace winrt::Windows::Networking::Vpn;

struct TestPacket : winrt::implements<TestPacket, IVpnPacketBuffer>
{
    winrt::Windows::Storage::Streams::Buffer bytes{ 20 };
    VpnPacketBufferStatus state = VpnPacketBufferStatus::Ok;
    uint32_t affinity = 0;
    auto Buffer() const { return bytes; }
    void Status(VpnPacketBufferStatus value) { state = value; }
    auto Status() const { return state; }
    void TransportAffinity(uint32_t value) { affinity = value; }
    auto TransportAffinity() const { return affinity; }
};

struct TestPacketList : winrt::implements<TestPacketList, IVpnPacketBufferList>
{
    std::deque<VpnPacketBuffer> packets;
    uint32_t removals = 0;
    VpnPacketBufferStatus state = VpnPacketBufferStatus::Ok;
    void Append(VpnPacketBuffer const& packet) { packets.push_back(packet); }
    void AddAtBegin(VpnPacketBuffer const& packet) { packets.push_front(packet); }
    VpnPacketBuffer RemoveAtBegin() { auto packet = packets.front(); packets.pop_front(); ++removals; return packet; }
    VpnPacketBuffer RemoveAtEnd() { auto packet = packets.back(); packets.pop_back(); return packet; }
    void Clear() { packets.clear(); }
    void Status(VpnPacketBufferStatus value) { state = value; }
    auto Status() const { return state; }
    uint32_t Size() const { return static_cast<uint32_t>(packets.size()); }
};

int wmain(int argc, wchar_t** argv)
{
    winrt::init_apartment();
    if (argc != 2) return 2;
    const auto module = LoadLibraryExW(argv[1], nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!module) { std::cerr << "LoadLibrary failed: " << GetLastError() << '\n'; return 1; }
    const auto activate = reinterpret_cast<HRESULT (__stdcall*)(void*, void**)>(GetProcAddress(module, "DllGetActivationFactory"));
    if (!activate) return 1;
    try
    {
        const winrt::hstring taskName{ swanbridge::BackgroundClass };
        winrt::Windows::Foundation::IActivationFactory factory{ nullptr };
        winrt::check_hresult(activate(winrt::get_abi(taskName), winrt::put_abi(factory)));
        const auto task = factory.ActivateInstance<winrt::Windows::ApplicationModel::Background::IBackgroundTask>();
        const winrt::hstring pluginName{ swanbridge::PluginClass };
        factory = nullptr;
        winrt::check_hresult(activate(winrt::get_abi(pluginName), winrt::put_abi(factory)));
        const auto plugin = factory.ActivateInstance<winrt::Windows::Networking::Vpn::IVpnPlugIn>();
        winrt::Windows::Networking::Vpn::VpnPacketBuffer keepAlive{ nullptr };
        plugin.GetKeepAlivePayload(nullptr, keepAlive);
        if (keepAlive) return 1;
        const auto input = winrt::make_self<TestPacketList>();
        const auto output = winrt::make_self<TestPacketList>();
        input->Append(winrt::make<TestPacket>().as<VpnPacketBuffer>());
        input->Append(winrt::make<TestPacket>().as<VpnPacketBuffer>());
        plugin.Encapsulate(nullptr, input.as<VpnPacketBufferList>(), output.as<VpnPacketBufferList>());
        if (input->Size() != 2 || input->removals != 2 || output->Size() != 0) return 1;
        const winrt::hstring unknown{ L"SwanBridge.DoesNotExist" };
        void* unexpected = nullptr;
        if (activate(winrt::get_abi(unknown), &unexpected) != CLASS_E_CLASSNOTAVAILABLE || unexpected) return 1;
        std::cout << "PASS background task activation\nPASS IVpnPlugIn activation\nPASS no fake keep-alive\n"
            "PASS outbound originals returned for platform cleanup\nPASS unknown class rejected\n";
        return 0;
    }
    catch (winrt::hresult_error const& error)
    {
        std::wcerr << L"FAIL 0x" << std::hex << static_cast<unsigned>(error.code()) << L" " << error.message().c_str() << '\n';
        return 1;
    }
}
