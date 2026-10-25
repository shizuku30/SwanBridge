#include "ProfileConfiguration.h"
#include <iostream>
#include <stdexcept>

using namespace swanbridge;
using namespace winrt;

void Check(bool condition, char const* description)
{
    if (!condition) throw std::runtime_error(description);
    std::cout << "PASS " << description << '\n';
}

bool Rejected(hstring const& xml)
{
    try { ParseProfile(xml); return false; }
    catch (hresult_error const&) { return true; }
}

hstring Changed(hstring const& xml, wchar_t const* attribute, wchar_t const* value)
{
    using namespace Windows::Data::Xml::Dom;
    XmlDocument doc; doc.LoadXml(xml);
    doc.SelectSingleNode(L"/SwanBridge/Ikev2").as<XmlElement>().SetAttribute(attribute, value);
    return doc.GetXml();
}

int main()
{
    init_apartment(apartment_type::multi_threaded);
    try
    {
        const hstring reference = L"{11111111-2222-3333-4444-555555555555}";
        ConnectionOptions options{ L"Test VPN", L"vpn.example.org", L"client", L"192.0.2.1" };
        const auto xml = SerializeProfile(options, reference);
        auto parsed = ParseProfile(xml, options.name);
        Check(xml == SerializeProfile(parsed.options, parsed.credentialReference), "schema v2 defaults round-trip without changes");
        Check(parsed.credentialReference == to_hstring(guid(reference)), "protected credential reference retained without reading or replacing the PSK");
        Check(std::wstring_view(xml).find(L"schemaVersion=\"2\"") != std::wstring_view::npos &&
            std::wstring_view(xml).find(L"psk=") == std::wstring_view::npos,
            "configuration contains a version and credential reference, never a PSK attribute");

        const hstring legacy = L"<SwanBridge schemaVersion=\"1\" engine=\"strongswan\"><Ikev2 server=\"vpn.example.org\" "
            L"localId=\"client\" remoteId=\"192.0.2.1\" localIdType=\"fqdn\" remoteIdType=\"ipv4\" "
            L"ikeProposal=\"aes256-sha256-modp2048\" espProposal=\"aes256-sha256\" "
            L"forceEncapsulation=\"true\" mobike=\"false\" credentialRef=\"{11111111-2222-3333-4444-555555555555}\"/></SwanBridge>";
        parsed = ParseProfile(legacy, options.name);
        Check(SerializeProfile(parsed.options, parsed.credentialReference) == xml, "legacy schema v1 upgrades to the exact existing defaults");
        Check(parsed.options.name == options.name, "profile display name comes from the selected Windows profile");
        Check(parsed.options.ikeRekey == 14400 && parsed.options.childRekeyPercent == 90 && parsed.options.rekeyJitter == 5,
            "legacy profiles receive bounded rekey defaults without changing credentials");
        Check(Rejected(Changed(xml, L"childRekeyPercent", L"100")) && Rejected(Changed(xml, L"ikeRekey", L"59")) &&
            Rejected(Changed(xml, L"rekeyJitter", L"26")), "invalid rekey timers fail closed in profile parsing");

        options.localIdType = SB_ID_IPV4; options.localId = L"192.0.2.2";
        options.remoteIdType = SB_ID_FQDN; options.remoteId = L"gateway.example.org";
        options.ikeProposal = L"aes128-sha256-modp2048"; options.espProposal = L"aes192-sha256";
        options.dpdDelay = 0; options.keepAlive = 45; options.retransmitTimeout = 5; options.retransmitTries = 6;
        options.keyingTries = 3; options.childLifetime = 3600; options.connectTimeout = 90;
        options.natPort = 14500; options.fragmentation = false; options.mtu = 1300;
        options.routeMode = 1; options.splitRoutes = L"192.0.2.0/24\n10.0.0.1/32";
        options.dnsMode = 1; options.customDns = L"10.77.0.1, 8.8.8.8"; options.excludeLocalSubnets = false;
        const auto custom = SerializeProfile(options, reference);
        parsed = ParseProfile(custom, options.name);
        Check(custom == SerializeProfile(parsed.options, parsed.credentialReference), "all advanced options round-trip without losing values");
        const auto policy = NativePolicy(parsed.options);
        Check(policy.local_id_type == SB_ID_IPV4 && policy.remote_id_type == SB_ID_FQDN &&
            !strcmp(policy.ike_proposal, "aes128-sha256-modp2048") && !strcmp(policy.esp_proposal, "aes192-sha256"),
            "selected identities and proposals reach the native engine contract");
        Check(policy.dpd_delay == 0 && policy.keep_alive == 45 && policy.retransmit_timeout == 5 && policy.retransmit_tries == 6 &&
            policy.keyingtries == 3 && policy.child_lifetime == 3600 && !policy.fragmentation && policy.nat_port == 14500,
            "selected timers, fragmentation and UDP port reach the native engine contract");
        Check(parsed.options.routeMode == 1 && parsed.options.dnsMode == 1 && !parsed.options.excludeLocalSubnets &&
            parsed.options.mtu == 1300 && parsed.options.connectTimeout == 90 &&
            parsed.options.splitRoutes == options.splitRoutes && parsed.options.customDns == options.customDns,
            "Windows channel options retain their independent routing and DNS policy");

        Check(Rejected(L""), "empty custom configuration rejected");
        Check(Rejected(hstring(std::wstring(32769, L'x'))), "oversized XML rejected");
        Check(Rejected(L"<SwanBridge>"), "malformed XML rejected");
        Check(Rejected(L"<!DOCTYPE SwanBridge [<!ENTITY test SYSTEM 'file:///SwanBridge-test'>]><SwanBridge>&test;</SwanBridge>"),
            "DTD and external-entity processing prohibited");
        Check(Rejected(Changed(xml, L"credentialRef", L"../secret")), "credential path traversal rejected before file access");
        Check(Rejected(Changed(xml, L"credentialRef", L"")), "missing credential reference rejected");
        Check(Rejected(Changed(xml, L"localIdType", L"email")), "unsupported identity type rejected");
        Check(Rejected(Changed(xml, L"remoteId", L"vpn.example.org")), "IPv4 identity cannot silently become a name");
        Check(Rejected(Changed(xml, L"ikeProposal", L"3des-sha1-modp1024")), "legacy proposal in stored XML rejected");
        Check(ParseProfile(Changed(xml, L"mobike", L"true")).options.mobike &&
            !ParseProfile(legacy).options.mobike, "MOBIKE round-trips explicitly while legacy profiles remain disabled");
        Check(Rejected(Changed(xml, L"mobike", L"yes")) && Rejected(Changed(xml, L"forceEncapsulation", L"false")),
            "MOBIKE values are strict and bare ESP remains unsupported");
        Check(Rejected(Changed(xml, L"keepAlive", L"4294967296")), "oversized integer cannot truncate in XML");
        Check(Rejected(Changed(xml, L"natPort", L"65536")), "oversized port cannot truncate to uint16");
        Check(Rejected(Changed(xml, L"dpdDelay", L"20s")), "timer parser requires a whole decimal value");
        Check(Rejected(Changed(xml, L"fragmentation", L"2")), "non-boolean fragmentation value rejected");
        using namespace Windows::Data::Xml::Dom;
        XmlDocument doc; doc.LoadXml(xml); doc.DocumentElement().SetAttribute(L"schemaVersion", L"999");
        Check(Rejected(doc.GetXml()), "future profile schemas are read-only rather than silently rewritten");
        doc.LoadXml(xml); doc.DocumentElement().SetAttribute(L"engine", L"other");
        Check(Rejected(doc.GetXml()), "foreign engine configuration rejected");
        doc.LoadXml(custom); doc.SelectSingleNode(L"/SwanBridge/Network").as<XmlElement>().SetAttribute(L"routes", L"192.0.2.1/24");
        Check(Rejected(doc.GetXml()), "invalid stored split route rejected");
        doc.LoadXml(custom); doc.SelectSingleNode(L"/SwanBridge/Network").as<XmlElement>().SetAttribute(L"dns", L"dns.example.org");
        Check(Rejected(doc.GetXml()), "custom DNS must contain literal IPv4 addresses");
        doc.LoadXml(custom); doc.SelectSingleNode(L"/SwanBridge/Network").as<XmlElement>().SetAttribute(L"excludeLocalSubnets", L"2");
        Check(Rejected(doc.GetXml()), "non-boolean local-subnet exclusion rejected");
        return 0;
    }
    catch (hresult_error const& error) { std::cerr << "FAIL profile XML HRESULT 0x" << std::hex << static_cast<unsigned>(error.code()) << '\n'; }
    catch (std::exception const& error) { std::cerr << "FAIL " << error.what() << '\n'; }
    return 1;
}
