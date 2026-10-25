#pragma once
#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include "engine/Policy.h"

namespace swanbridge
{
    inline constexpr wchar_t EngineUnavailable[] =
        L"SB1001: The IKEv2 engine is not connected. No VPN tunnel was created.";
    inline constexpr wchar_t InvalidConfiguration[] =
        L"SB1002: Invalid SwanBridge connection configuration.";
    inline constexpr wchar_t BackgroundClass[] = L"SwanBridge.Plugin.BackgroundTask";
    inline constexpr wchar_t PluginClass[] = L"SwanBridge.Plugin.VpnPlugIn";
    // More-specific routes remain effective when a new physical default has a lower metric.
    inline constexpr wchar_t FullTunnelIpv4Routes[] = L"0.0.0.0/1,128.0.0.0/1";
    // Local-only address for the full-tunnel IPv6 sink; never advertised as a negotiated server address.
    inline constexpr wchar_t Ipv6GuardAddress[] = L"fe80::5357:414e:4252:4944";

    struct ConnectionOptions
    {
        std::wstring name;
        std::wstring server;
        std::wstring localId;
        std::wstring remoteId;
        std::wstring ikeProposal = L"aes256-sha256-modp2048";
        std::wstring espProposal = L"aes256-sha256";
        std::uint16_t port = 500;
        std::uint16_t natPort = 4500;
        bool forceEncapsulation = true;
        bool mobike = false;
        std::uint32_t localIdType = SB_ID_FQDN;
        std::uint32_t remoteIdType = SB_ID_IPV4;
        std::uint32_t dpdDelay = 20, keepAlive = 15, retransmitTimeout = 1, retransmitTries = 3;
        std::uint32_t keyingTries = 1, childLifetime = 86400, connectTimeout = 25, mtu = 1280;
        std::uint32_t ikeRekey = 14400, childRekeyPercent = 90, rekeyJitter = 5;
        bool fragmentation = true, excludeLocalSubnets = true;
        std::uint32_t routeMode = 0, dnsMode = 0;
        std::wstring splitRoutes, customDns;
    };

    inline bool ParseUnsigned(std::wstring_view value, std::uint32_t& number)
    {
        if (value.empty() || value.size() > 10) return false;
        std::uint64_t parsed = 0;
        for (auto c : value)
        {
            if (c < L'0' || c > L'9') return false;
            parsed = parsed * 10 + (c - L'0');
            if (parsed > UINT32_MAX) return false;
        }
        number = static_cast<std::uint32_t>(parsed);
        return true;
    }

    inline bool ParseIPv4(std::wstring_view text, std::uint32_t& address)
    {
        address = 0;
        for (int part = 0; part < 4; ++part)
        {
            const auto dot = text.find(L'.');
            const auto token = text.substr(0, dot);
            std::uint32_t octet;
            if ((token.size() > 1 && token.front() == L'0') || !ParseUnsigned(token, octet) || octet > 255) return false;
            address = (address << 8) | octet;
            if (part == 3) return dot == std::wstring_view::npos;
            if (dot == std::wstring_view::npos) return false;
            text.remove_prefix(dot + 1);
        }
        return false;
    }

    inline std::vector<std::wstring> Tokens(std::wstring_view text)
    {
        std::vector<std::wstring> tokens;
        while (!text.empty())
        {
            const auto start = text.find_first_not_of(L" ,;\r\n\t");
            if (start == std::wstring_view::npos) break;
            text.remove_prefix(start);
            const auto end = text.find_first_of(L" ,;\r\n\t");
            tokens.emplace_back(text.substr(0, end));
            if (end == std::wstring_view::npos) break;
            text.remove_prefix(end);
        }
        return tokens;
    }

    inline bool ParseRoute(std::wstring_view text, std::wstring& address, std::uint8_t& prefix)
    {
        const auto slash = text.find(L'/');
        if (slash == std::wstring_view::npos) return false;
        std::uint32_t ip, bits;
        if (!ParseIPv4(text.substr(0, slash), ip) || !ParseUnsigned(text.substr(slash + 1), bits) || bits == 0 || bits > 32) return false;
        if ((ip & (UINT32_MAX << (32 - bits))) != ip) return false;
        address = text.substr(0, slash);
        prefix = static_cast<std::uint8_t>(bits);
        return true;
    }

    inline bool AsciiEquals(std::wstring_view value, char const* ascii)
    {
        const auto size = strlen(ascii);
        if (value.size() != size) return false;
        for (std::size_t i = 0; i < size; ++i) if (value[i] != static_cast<unsigned char>(ascii[i])) return false;
        return true;
    }

    inline sb_policy NativePolicy(ConnectionOptions const& options)
    {
        auto policy = sb_policy_defaults();
        policy.ike_proposal = nullptr;
        policy.esp_proposal = nullptr;
        for (auto proposal : sb_ike_proposals) if (AsciiEquals(options.ikeProposal, proposal)) policy.ike_proposal = proposal;
        for (auto proposal : sb_esp_proposals) if (AsciiEquals(options.espProposal, proposal)) policy.esp_proposal = proposal;
        policy.local_id_type = options.localIdType; policy.remote_id_type = options.remoteIdType;
        policy.dpd_delay = options.dpdDelay; policy.keep_alive = options.keepAlive;
        policy.retransmit_timeout = options.retransmitTimeout; policy.retransmit_tries = options.retransmitTries;
        policy.keyingtries = options.keyingTries; policy.child_lifetime = options.childLifetime;
        policy.fragmentation = options.fragmentation; policy.nat_port = options.natPort;
        return policy;
    }

    inline sb_rekey_policy NativeRekeyPolicy(ConnectionOptions const& options)
    {
        auto policy = sb_rekey_policy_defaults();
        policy.ike_time = options.ikeRekey;
        policy.child_percent = options.childRekeyPercent;
        policy.jitter_percent = options.rekeyJitter;
        return policy;
    }

    inline bool ValidName(std::wstring_view name)
    {
        return !name.empty() && name.size() <= 128 &&
            std::none_of(name.begin(), name.end(), [](wchar_t c) { return c < 32 || c == L'\\' || c == L'/' || c == L':'; });
    }

    inline bool ValidServer(std::wstring_view server)
    {
        if (server.empty() || server.size() > 253 || server.front() == L'.' ||
            server.back() == L'.' || server.front() == L'-' || server.back() == L'-')
        {
            return false;
        }
        std::size_t labelLength = 0;
        wchar_t previous = 0;
        for (wchar_t c : server)
        {
            if (c == L'.')
            {
                if (!labelLength || labelLength > 63 || previous == L'-') return false;
                labelLength = 0;
            }
            else
            {
                const bool alphanumeric = (c >= L'a' && c <= L'z') ||
                    (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9');
                if ((!alphanumeric && c != L'-') || (!labelLength && c == L'-')) return false;
                ++labelLength;
            }
            previous = c;
        }
        return labelLength > 0 && labelLength <= 63;
    }

    inline bool ValidIdentity(std::wstring_view identity)
    {
        return !identity.empty() && identity.size() <= 255 &&
            std::none_of(identity.begin(), identity.end(), [](wchar_t c) { return c < 32; });
    }

    inline bool ValidOptions(ConnectionOptions const& options)
    {
        auto policy = NativePolicy(options);
        auto rekey = NativeRekeyPolicy(options);
        std::uint32_t address;
        if (!ValidName(options.name) || !ValidServer(options.server) || !sb_policy_valid(&policy) || !sb_rekey_policy_valid(&rekey) ||
            !ValidIdentity(options.localId) || !ValidIdentity(options.remoteId) ||
            (options.localIdType == SB_ID_IPV4 ? !ParseIPv4(options.localId, address) : !ValidServer(options.localId)) ||
            (options.remoteIdType == SB_ID_IPV4 ? !ParseIPv4(options.remoteId, address) : !ValidServer(options.remoteId)) ||
            options.port != 500 || !options.forceEncapsulation ||
            options.connectTimeout < 5 || options.connectTimeout > 120 || options.mtu < 576 || options.mtu > 1400 ||
            options.routeMode > 1 || options.dnsMode > 2 || options.splitRoutes.size() > 4096 || options.customDns.size() > 512) return false;
        if (options.routeMode == 1)
        {
            const auto routes = Tokens(options.splitRoutes);
            if (routes.empty() || routes.size() > 32) return false;
            for (auto const& route : routes)
            {
                std::wstring network; std::uint8_t prefix;
                if (!ParseRoute(route, network, prefix)) return false;
            }
        }
        if (options.dnsMode == 1)
        {
            const auto servers = Tokens(options.customDns);
            if (servers.empty() || servers.size() > 4) return false;
            for (auto const& server : servers) if (!ParseIPv4(server, address) || !address || address == UINT32_MAX) return false;
        }
        return true;
    }
}
