#pragma once
#include <stdexcept>
#include <winrt/Windows.Data.Xml.Dom.h>
#include "EngineContract.h"

namespace swanbridge
{
    struct ProfileSettings
    {
        ConnectionOptions options;
        winrt::hstring credentialReference;
    };

    inline winrt::hstring CanonicalCredentialReference(winrt::hstring const& reference)
    {
        try { return winrt::to_hstring(winrt::guid(reference)); }
        catch (std::invalid_argument const&) { throw winrt::hresult_invalid_argument(InvalidConfiguration); }
    }

    inline winrt::hstring SerializeProfile(ConnectionOptions const& options, winrt::hstring const& reference)
    {
        using namespace winrt::Windows::Data::Xml::Dom;
        if (!ValidOptions(options)) throw winrt::hresult_invalid_argument(InvalidConfiguration);
        const auto credential = CanonicalCredentialReference(reference);
        XmlDocument doc;
        const auto root = doc.CreateElement(L"SwanBridge");
        root.SetAttribute(L"schemaVersion", L"2"); root.SetAttribute(L"engine", L"strongswan");
        doc.AppendChild(root);
        const auto ike = doc.CreateElement(L"Ikev2");
        root.AppendChild(ike);
        ike.SetAttribute(L"server", options.server);
        ike.SetAttribute(L"localId", options.localId); ike.SetAttribute(L"remoteId", options.remoteId);
        ike.SetAttribute(L"localIdType", options.localIdType == SB_ID_FQDN ? L"fqdn" : L"ipv4");
        ike.SetAttribute(L"remoteIdType", options.remoteIdType == SB_ID_FQDN ? L"fqdn" : L"ipv4");
        ike.SetAttribute(L"ikeProposal", options.ikeProposal); ike.SetAttribute(L"espProposal", options.espProposal);
        ike.SetAttribute(L"credentialRef", credential);
        ike.SetAttribute(L"forceEncapsulation", L"true"); ike.SetAttribute(L"mobike", options.mobike ? L"true" : L"false");
        const auto set = [&](wchar_t const* key, std::uint32_t value) { ike.SetAttribute(key, winrt::to_hstring(value)); };
        set(L"dpdDelay", options.dpdDelay); set(L"keepAlive", options.keepAlive);
        set(L"retransmitTimeout", options.retransmitTimeout); set(L"retransmitTries", options.retransmitTries);
        set(L"keyingTries", options.keyingTries); set(L"childLifetime", options.childLifetime);
        set(L"ikeRekey", options.ikeRekey); set(L"childRekeyPercent", options.childRekeyPercent);
        set(L"rekeyJitter", options.rekeyJitter);
        set(L"connectTimeout", options.connectTimeout); set(L"natPort", options.natPort);
        set(L"fragmentation", options.fragmentation);
        const auto network = doc.CreateElement(L"Network");
        root.AppendChild(network);
        network.SetAttribute(L"mtu", winrt::to_hstring(options.mtu));
        network.SetAttribute(L"routeMode", winrt::to_hstring(options.routeMode));
        network.SetAttribute(L"dnsMode", winrt::to_hstring(options.dnsMode));
        network.SetAttribute(L"excludeLocalSubnets", options.excludeLocalSubnets ? L"1" : L"0");
        network.SetAttribute(L"routes", options.splitRoutes); network.SetAttribute(L"dns", options.customDns);
        return doc.GetXml();
    }

    inline ProfileSettings ParseProfile(winrt::hstring const& xml, std::wstring name = L"SwanBridge")
    {
        using namespace winrt::Windows::Data::Xml::Dom;
        if (xml.empty() || xml.size() > 32768) throw winrt::hresult_invalid_argument(InvalidConfiguration);
        XmlLoadSettings load;
        load.ProhibitDtd(true); load.ResolveExternals(false); load.MaxElementDepth(8);
        XmlDocument doc;
        doc.LoadXml(xml, load);
        const auto root = doc.DocumentElement();
        const auto ike = doc.SelectSingleNode(L"/SwanBridge/Ikev2").try_as<XmlElement>();
        if (!root || !ike || root.GetAttribute(L"engine") != L"strongswan" ||
            (root.GetAttribute(L"schemaVersion") != L"1" && root.GetAttribute(L"schemaVersion") != L"2"))
            throw winrt::hresult_invalid_argument(InvalidConfiguration);
        ProfileSettings result;
        auto& options = result.options;
        options.name = std::move(name);
        options.server = ike.GetAttribute(L"server");
        options.localId = ike.GetAttribute(L"localId"); options.remoteId = ike.GetAttribute(L"remoteId");
        const auto identity = [&](wchar_t const* key) -> std::uint32_t
        {
            const auto value = ike.GetAttribute(key);
            if (value == L"fqdn") return SB_ID_FQDN;
            if (value == L"ipv4") return SB_ID_IPV4;
            throw winrt::hresult_invalid_argument(InvalidConfiguration);
        };
        options.localIdType = identity(L"localIdType"); options.remoteIdType = identity(L"remoteIdType");
        options.ikeProposal = ike.GetAttribute(L"ikeProposal"); options.espProposal = ike.GetAttribute(L"espProposal");
        if (ike.GetAttribute(L"forceEncapsulation") != L"true" ||
            (ike.GetAttribute(L"mobike") != L"false" && ike.GetAttribute(L"mobike") != L"true"))
            throw winrt::hresult_invalid_argument(InvalidConfiguration);
        options.mobike = ike.GetAttribute(L"mobike") == L"true";
        result.credentialReference = CanonicalCredentialReference(ike.GetAttribute(L"credentialRef"));
        const auto number = [&](XmlElement const& node, wchar_t const* key, std::uint32_t fallback)
        {
            if (!node.GetAttributeNode(key)) return fallback;
            std::uint32_t value;
            if (!ParseUnsigned(node.GetAttribute(key).c_str(), value)) throw winrt::hresult_invalid_argument(InvalidConfiguration);
            return value;
        };
        options.dpdDelay = number(ike, L"dpdDelay", options.dpdDelay);
        options.keepAlive = number(ike, L"keepAlive", options.keepAlive);
        options.retransmitTimeout = number(ike, L"retransmitTimeout", options.retransmitTimeout);
        options.retransmitTries = number(ike, L"retransmitTries", options.retransmitTries);
        options.keyingTries = number(ike, L"keyingTries", options.keyingTries);
        options.childLifetime = number(ike, L"childLifetime", options.childLifetime);
        options.ikeRekey = number(ike, L"ikeRekey", options.ikeRekey);
        options.childRekeyPercent = number(ike, L"childRekeyPercent", options.childRekeyPercent);
        options.rekeyJitter = number(ike, L"rekeyJitter", options.rekeyJitter);
        options.connectTimeout = number(ike, L"connectTimeout", options.connectTimeout);
        const auto port = number(ike, L"natPort", options.natPort);
        const auto fragmentation = number(ike, L"fragmentation", options.fragmentation);
        if (!port || port > 65535 || fragmentation > 1) throw winrt::hresult_invalid_argument(InvalidConfiguration);
        options.natPort = static_cast<std::uint16_t>(port); options.fragmentation = fragmentation != 0;
        if (const auto network = doc.SelectSingleNode(L"/SwanBridge/Network").try_as<XmlElement>())
        {
            options.mtu = number(network, L"mtu", options.mtu);
            options.routeMode = number(network, L"routeMode", options.routeMode);
            options.dnsMode = number(network, L"dnsMode", options.dnsMode);
            const auto exclude = number(network, L"excludeLocalSubnets", options.excludeLocalSubnets);
            if (exclude > 1) throw winrt::hresult_invalid_argument(InvalidConfiguration);
            options.excludeLocalSubnets = exclude != 0;
            options.splitRoutes = network.GetAttribute(L"routes"); options.customDns = network.GetAttribute(L"dns");
        }
        if (!ValidOptions(options)) throw winrt::hresult_invalid_argument(InvalidConfiguration);
        return result;
    }
}
