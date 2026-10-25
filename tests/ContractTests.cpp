#include "EngineContract.h"
#include "RecoveryPolicy.h"
#include "ProfileEditorState.h"
#include "ThemePolicy.h"
#include "LanguagePolicy.h"
#include <iostream>
#include <stdexcept>

void Check(bool condition, char const* description)
{
    if (!condition) throw std::runtime_error(description);
    std::cout << "PASS " << description << '\n';
}

int main()
{
    using namespace swanbridge;
    try
    {
        Check(ValidName(L"SwanBridge"), "valid profile name");
        Check(!ValidName(L""), "empty profile rejected");
        Check(!ValidName(L"bad\nname"), "control character rejected");
        Check(!ValidName(L"bad/name"), "path separator rejected");
        Check(!ValidName(std::wstring(L"bad\0name", 8)), "embedded null rejected");
        Check(ValidServer(L"vpn.example.org"), "hostname accepted");
        Check(ValidServer(L"192.0.2.1"), "IPv4 literal accepted");
        Check(!ValidServer(L"https://vpn.example.org"), "URL rejected");
        Check(!ValidServer(L"host:4500"), "port in hostname rejected");
        Check(!ValidServer(L"vpn..example.org"), "empty DNS label rejected");
        Check(!ValidServer(L"vpn.-example.org"), "label prefix hyphen rejected");
        Check(!ValidServer(L"vpn-.example.org"), "label suffix hyphen rejected");
        Check(!ValidServer(std::wstring(64, L'a') + L".org"), "oversized DNS label rejected");
        Check(!ValidIdentity(L"id\n"), "invalid identity rejected");
        ConnectionOptions options{ L"Test", L"vpn.example.org", L"client", L"192.0.2.1" };
        Check(ValidOptions(options), "compatible secure defaults accepted");
        const auto fullRoutes = Tokens(FullTunnelIpv4Routes);
        std::wstring fullAddress;
        std::uint8_t fullPrefix = 0;
        Check(fullRoutes.size() == 2 &&
            ParseRoute(fullRoutes[0], fullAddress, fullPrefix) && fullAddress == L"0.0.0.0" && fullPrefix == 1 &&
            ParseRoute(fullRoutes[1], fullAddress, fullPrefix) && fullAddress == L"128.0.0.0" && fullPrefix == 1,
            "full-tunnel IPv4 routes cover both halves and outrank every physical default metric");
        options.ikeProposal = L"3des-sha1-modp1024";
        Check(!ValidOptions(options), "legacy IKE proposal rejected");
        options.ikeProposal = L"aes256-sha256-modp2048";
        options.mobike = true;
        Check(ValidOptions(options), "MOBIKE is a supported per-profile opt-in");
        options.mobike = false;
        const auto defaults = options;
        auto rekey = NativeRekeyPolicy(options);
        Check(sizeof(rekey) == 20 && sb_rekey_policy_valid(&rekey) && rekey.ike_time == 14400 &&
            rekey.child_percent == 90 && rekey.jitter_percent == 5, "bounded proactive rekey defaults have a separate ABI");
        options.ikeRekey = 0; options.childRekeyPercent = 0;
        Check(ValidOptions(options), "proactive rekey can be disabled independently of peer-initiated support");
        options = defaults; options.ikeRekey = 59;
        Check(!ValidOptions(options), "excessively short IKE rekey timer rejected");
        options = defaults; options.childRekeyPercent = 100;
        Check(!ValidOptions(options), "Child rekey must precede the hard lifetime");
        options = defaults; options.rekeyJitter = 26;
        Check(!ValidOptions(options), "excessive rekey jitter rejected");
        options = defaults;
        auto policy = NativePolicy(options);
        Check(sizeof(policy) == 64 && sb_policy_valid(&policy), "versioned native policy preserves the x64 ABI");
        Check(policy.dpd_delay == 20 && policy.keep_alive == 15 && policy.retransmit_timeout == 1 &&
            policy.retransmit_tries == 3 && policy.keyingtries == 1 && policy.child_lifetime == 86400 &&
            policy.nat_port == 4500 && policy.fragmentation == 1, "legacy engine timer and transport defaults preserved");
        for (auto proposal : sb_ike_proposals)
        {
            options.ikeProposal.assign(proposal, proposal + strlen(proposal));
            Check(ValidOptions(options), "supported IKE proposal accepted");
        }
        for (auto proposal : sb_esp_proposals)
        {
            options.espProposal.assign(proposal, proposal + strlen(proposal));
            Check(ValidOptions(options), "supported ESP proposal accepted");
        }
        options = defaults; options.localIdType = SB_ID_IPV4; options.localId = L"192.0.2.2";
        options.remoteIdType = SB_ID_FQDN; options.remoteId = L"vpn.example.org";
        Check(ValidOptions(options), "both identity types supported on either peer");
        options.localId = L"client";
        Check(!ValidOptions(options), "identity value must match its selected type");
        options = defaults; options.natPort = 0;
        Check(!ValidOptions(options), "zero NAT port rejected");
        options = defaults; options.mtu = 1401;
        Check(!ValidOptions(options), "oversized MTU rejected");
        options.mtu = 575;
        Check(!ValidOptions(options), "undersized MTU rejected");
        options = defaults; options.connectTimeout = 121;
        Check(!ValidOptions(options), "unbounded connection timeout rejected");
        options = defaults; options.dpdDelay = 301;
        Check(!ValidOptions(options), "unbounded DPD interval rejected");
        options = defaults; options.keepAlive = 0;
        Check(!ValidOptions(options), "unsupported NAT keepalive disable rejected");
        options = defaults; options.childLifetime = 299;
        Check(!ValidOptions(options), "unsupported short Child SA lifetime rejected");
        options = defaults; options.retransmitTries = 9;
        Check(!ValidOptions(options), "excessive retransmission count rejected");
        options = defaults; options.dpdDelay = 0;
        Check(ValidOptions(options), "explicitly disabling active DPD is supported");
        options = defaults; options.routeMode = 1;
        Check(!ValidOptions(options), "split routing requires explicit networks");
        options.splitRoutes = L"192.0.2.0/24\n10.0.0.1/32";
        Check(ValidOptions(options), "canonical split routes accepted");
        options.splitRoutes = L"192.0.2.1/24";
        Check(!ValidOptions(options), "CIDR host bits cannot silently change the requested network");
        options.splitRoutes = L"0.0.0.0/0";
        Check(!ValidOptions(options), "default route requires full-tunnel mode");
        options.splitRoutes.clear();
        for (int i = 0; i < 33; ++i) options.splitRoutes += L"10.0.0.1/32 ";
        Check(!ValidOptions(options), "split route count is bounded");
        options = defaults; options.dnsMode = 1;
        Check(!ValidOptions(options), "custom DNS mode requires addresses");
        options.customDns = L"10.77.0.1, 8.8.8.8";
        Check(ValidOptions(options), "multiple custom IPv4 DNS servers accepted");
        options.customDns = L"1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5";
        Check(!ValidOptions(options), "custom DNS count is bounded");
        options.customDns = L"0.0.0.0";
        Check(!ValidOptions(options), "unspecified DNS address rejected");
        options.customDns = L"255.255.255.255";
        Check(!ValidOptions(options), "broadcast DNS address rejected");
        std::uint32_t number;
        Check(ParseUnsigned(L"4294967295", number) && number == UINT32_MAX, "maximum uint32 parsed without truncation");
        Check(!ParseUnsigned(L"4294967296", number) && !ParseUnsigned(L"-1", number) &&
            !ParseUnsigned(L" 20", number) && !ParseUnsigned(L"1x", number), "overflow and non-decimal timer values rejected");
        Check(!ParseIPv4(L"10.01.0.1", number) && !ParseIPv4(L"256.0.0.1", number) &&
            !ParseIPv4(L"10.0.1", number) && !ParseIPv4(L"10.0.0.1.2", number), "ambiguous or malformed IPv4 addresses rejected");
        Check(!ValidName(L"name\x0001"), "all profile-name control characters rejected");
        ProfileEditorState saved{{L"Profile", L"vpn.example.org", L"4500"}, true};
        auto edited = saved;
        Check(!HasEditorChanges(edited, saved, false), "deferred UI initialization events cannot mark unchanged fields as edited");
        edited.fields[2] = L"invalid input";
        Check(HasEditorChanges(edited, saved, false), "invalid unsaved field edits still require confirmation");
        edited = saved; edited.excludeLocalSubnets = false;
        Check(HasEditorChanges(edited, saved, false), "toggle edits participate in unsaved-change detection");
        edited = saved;
        Check(!HasEditorChanges(edited, saved, false), "reverting an edit removes the unsaved-change prompt");
        Check(HasEditorChanges(edited, saved, true), "a newly entered PSK is detected without copying it into the editor snapshot");
        Check(SystemPaletteIsDark(255, 255, 255), "light system foreground selects the dark UI palette");
        Check(!SystemPaletteIsDark(0, 0, 0), "dark system foreground selects the light UI palette");
        Check(!SystemPaletteIsDark(128, 128, 128) && SystemPaletteIsDark(129, 129, 129), "system palette threshold is deterministic");
        for (auto const* language : { L"zh-CN", L"zh-SG", L"zh-Hans", L"zh-Hans-CN", L"ZH-hAnS-sg", L"zh-Hans-HK" })
            Check(std::wstring_view(SelectUiLanguage(language)) == L"zh-Hans", "Simplified Chinese uses the zh-Hans catalog");
        for (auto const* language : { L"en-US", L"en-GB", L"fr-FR", L"ja-JP", L"ar-SA", L"", L"zh", L"zh-TW", L"zh-HK", L"zh-MO", L"zh-Hant", L"zh-Hant-CN", L"zhx-CN" })
            Check(std::wstring_view(SelectUiLanguage(language)) == L"en-US", "all other primary languages fall back to English");
        Check(FormatUiText(L"Loaded {0} connections.", L"3") == L"Loaded 3 connections.", "localized messages format data without concatenating translated fragments");
        Check(FormatUiText(L"{0}", L"{0}") == L"{0}", "message arguments are not recursively interpreted");
        Check(FormatUiText(L"Ready.", L"3") == L"Ready.", "unformatted localized status remains unchanged");
        Check(AcceptanceDropActive(1000, 100000, 11000), "bounded acceptance outage enabled");
        Check(!AcceptanceDropActive(11000, 100000, 11000), "expired outage automatically disabled");
        Check(!AcceptanceDropActive(1000, 1000, 11000), "expired lease cannot disrupt traffic");
        Check(!AcceptanceDropActive(1000, 100000, 121001), "outage beyond two minutes rejected");
        Check(!AcceptanceDropActive(1000, 100000, 100001), "outage beyond its lease rejected");
        Check(!AcceptanceDropActive(1000, 15000000, 11000), "unbounded acceptance lease rejected");
        Check(!AcceptanceDropActive(-1, 100000, 11000), "invalid acceptance clock rejected");
        return 0;
    }
    catch (std::exception const& error)
    {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
