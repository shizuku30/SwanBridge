<div align="center">

<img src="package/Assets/SwanBridge.png" width="96" height="96" alt="SwanBridge VPN icon" />

# SwanBridge VPN

**Standards-based IKEv2-PSK for Windows.**

<a href="#requirements"><img src="https://img.shields.io/badge/Windows-10%20%2F%2011-0078D4" alt="Windows 10 / 11" /></a>
<a href="#build-from-source"><img src="https://img.shields.io/badge/C%2B%2B-20-00599C" alt="C++20" /></a>
<a href="#how-it-works"><img src="https://img.shields.io/badge/UI-UWP-7A3E9D" alt="Native UWP" /></a>
<br />
<a href="https://github.com/shizuku30/SwanBridge/actions/workflows/ci.yml"><img src="https://github.com/shizuku30/SwanBridge/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI" /></a>
<a href="#compatibility-and-limitations"><img src="https://img.shields.io/badge/architecture-x64-455A64" alt="x64" /></a>
<a href="LICENSING.md"><img src="https://img.shields.io/badge/license-GPL--2.0--or--later-2E7D32" alt="GPL-2.0-or-later source license" /></a>

</div>

## Overview

SwanBridge brings **IKEv2 with pre-shared-key authentication to Windows**.
Modern mobile platforms already provide this capability through their VPN APIs
or configuration profiles, including
[Android](https://developer.android.com/reference/android/net/Ikev2VpnProfile.Builder#setAuthPsk(byte[]))
and [iOS](https://developer.apple.com/documentation/networkextension/nevpnikeauthenticationmethod).
The project provides a native Windows VPN provider for the same standards-based
authentication model.

Built around strongSwan 6.1.0, it uses standard IKEv2/IPsec rather than a
vendor-specific handshake. The Windows integration combines C++/WinRT, UWP and
the Windows VPN data channel. No commercial VPN executables, libraries or
drivers are reused. The current package version is **v0.1.0.49**.

## Features

- Authenticate with mutual IKEv2 PSK and negotiate an IPv4 Child SA.
- Encrypt and decrypt ESP traffic through strongSwan libipsec.
- Create and manage this provider's Windows VPN profiles.
- Configure IKE/ESP proposals, liveness, retransmission, rekey, routing and DNS.
- Support full/split IPv4 routing and optional local-subnet exclusions.
- Negotiate opt-in IPv4 MOBIKE without replacing the authenticated session.
- Handle proactive and peer-initiated IKE and Child SA rekeys.
- Run command-line offline regressions and separate live-network acceptance tests.

## Protocol Support

| Protocol | Implementation scope |
| --- | --- |
| [IKEv2 (RFC 7296)](https://www.rfc-editor.org/rfc/rfc7296) | Mutual PSK authentication, peer identities, configuration payloads, Child SA negotiation and rekey. |
| [ESP (RFC 4303)](https://www.rfc-editor.org/rfc/rfc4303) | IPv4 tunnel traffic, encryption, integrity protection and anti-replay handling through libipsec. |
| [MOBIKE (RFC 4555)](https://www.rfc-editor.org/rfc/rfc4555) | Negotiated IPv4 client network migration while retaining the authenticated session. |
| [IKE fragmentation (RFC 7383)](https://www.rfc-editor.org/rfc/rfc7383) | Fragmented IKE messages when supported by both peers. |

Server compatibility depends on matching authentication identities, proposals,
traffic selectors and policy. Standards-based protocol support is not a claim
that every gateway or every optional IKEv2 feature has been tested.

## Requirements

- Windows 10 version 2004 or later, or Windows 11.
- An x64 Windows installation.
- The x64 Microsoft.VCLibs.140.00 framework for an installed application.
- A reachable IKEv2 server supporting mutual PSK, IPv4 virtual addresses and
  UDP-encapsulated ESP.
- Server-side MOBIKE support when testing network migration.

## Usage

1. Build, sign and install the development package as described below.
2. Open SwanBridge and add a connection.
3. Enter your gateway, local identity, remote identity and PSK.
4. Review the advanced settings, then save the profile.
5. Connect or disconnect through Windows VPN settings.

Select an existing connection to inspect its configuration. Disconnect it before
editing. Leaving its PSK field blank retains the encrypted key; a stored key is
never displayed. Other providers' profiles are not modified.

The generic Windows Add VPN form does not collect SwanBridge's explicit IKE
identities and PSK, so initial provisioning still uses the companion app.

## How It Works

| Component | Role |
| --- | --- |
| `src/App.cpp` | Native C++/WinRT and UWP profile management application. |
| `src/Plugin.cpp` / `src/Host.cpp` | Windows VPN provider and dedicated background host. |
| `src/engine` | strongSwan libcharon/libipsec bridge for IKEv2, ESP, MOBIKE and rekey. |
| `src/EngineContract.h` / `src/ProfileConfiguration.h` | Versioned engine contract and validated profile serialization. |
| `package` | MSIX packaging metadata and application assets. |
| `scripts` / `tests` | Reproducible builds, offline regressions and opt-in acceptance tools. |

A plain C ABI isolates the MinGW engine from the MSVC provider. Windows receives
an interface only after an authenticated IPv4 Child SA is available. Network
migration and rekey update the protocol state without treating a fresh login
as continuity.

## Security Model

- PSKs use data protection scoped to the current Windows user.
- Profile XML stores an opaque credential reference rather than the key.
- Diagnostic tools pass secrets through anonymous stdin, not command arguments.
- Engine DLLs and build dependencies resolve relative to the project or package.
- Profile updates validate ownership, disconnected state and unchanged source XML.
- Full-tunnel mode captures and drops public IPv6 rather than allowing an IPv6 bypass.
- CI does not install an application, import certificate trust, connect a VPN
  or access a deployment.

See [SECURITY.md](SECURITY.md) before sharing a report. Connection exports,
router backups, raw diagnostics, packet captures and signing material must stay
private.

## Compatibility and Limitations

- The tunnel carries IPv4 only. Split mode leaves unrelated IPv6 outside the VPN.
- Certificate/EAP authentication, proactive reauthentication and ESP PFS
  configuration are not exposed as supported options.
- There is no system-wide kill switch or native Always On VPN guarantee.
- MOBIKE is limited to IPv4 client path changes to the same reachable gateway
  address and UDP port. Long outages can still exceed the liveness budget.
- Local and remote subnet overlap requires explicit routing decisions.
- Removing a Windows profile does not yet clean up orphaned protected key files.
- Concurrent tunnels and indefinite unattended operation are not validated.

## Build From Source

Install Git, Visual Studio C++ tools and a Windows SDK containing C++/WinRT
headers. No C# or .NET Native build is needed. Use a checkout without spaces,
or an available NTFS short path, for the Autotools core build.

Run from the repository root in Windows PowerShell:

```powershell
.\scripts\Initialize-Toolchain.ps1 -InstallPackages
.\scripts\Fetch-Upstream.ps1
.\scripts\Build-Core.ps1
.\scripts\Build.ps1
```

The isolated MSYS2/MinGW/OpenSSL toolchain stays under ignored `tools/`.
Upstream source and download hashes are pinned in `upstream.lock.json`.
The build produces an unsigned MSIX in `dist/`.

Local development signing and installation are separate:

```powershell
.\scripts\Sign-Dev.ps1
.\scripts\Install-Signed.ps1
```

Review the development publisher before establishing certificate trust.
Signing does not import trust, and an upstream open-source license does not
transfer its signing identity. Never install an update over an active VPN
session.

See the [development guide](docs/DEVELOPMENT.md) for process-scoped execution
policy, desktop test forwarders, installation details and advanced options.

## Automated Tests

`Build.ps1` runs the Windows offline suite by default. Publication checks can
also be run independently:

```powershell
.\scripts\Test-RepositoryHygiene.ps1
.\tests\RepositoryHygieneTests.ps1
.\tests\PublicationTests.ps1
```

| CI job | Coverage |
| --- | --- |
| Windows x64 | Native engine, protocol contracts, mobility/rekey regressions, ABI, profile parsing, credential protection, activation and both MSIX configurations. |

Actions use immutable commit pins and read-only repository permissions.
Only offline build/test logs are uploaded, with 14-day retention. There are no
automatic signed releases or installable CI artifacts.

Real traffic, physical network changes and actual suspend/resume remain separate
operator-run checks. See [live acceptance](docs/DEVELOPMENT.md#live-acceptance).

## Contributing

Focused bug reports and pull requests are welcome. Read
[CONTRIBUTING.md](CONTRIBUTING.md) for source and validation rules.
Report vulnerabilities through a private channel as described in
[SECURITY.md](SECURITY.md). Do not submit real deployment settings or credentials.

## Disclaimer

SwanBridge is independent of strongSwan and Microsoft and is not affiliated with
or endorsed by either project. Names and trademarks belong to their respective
owners. This development build is not a security audit or a production assurance.

## License

Original source, scripts, tests, documentation and the authorized icon use
**GPL-2.0-or-later**. The OpenSSL 3-linked combined Windows binary must use
**GPL-3.0-or-later**, retaining the applicable third-party notices and corresponding
source obligations.

See [LICENSE](LICENSE), [LICENSING.md](LICENSING.md) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the full terms and attribution.
