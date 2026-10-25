# Development and acceptance

An independent Windows IKEv2/IPsec VPN provider built around strongSwan 6.1.0.
This is a community development project, not an official strongSwan product.

The current package version is **v0.1.0.49**. The native UWP architecture is
retained: a C++/WinRT editor, a Windows VPN plugin and host, and an isolated
MinGW-built engine connected through a versioned C ABI.

## Features and scope

- Mutual IKEv2 PSK authentication and an authenticated IPv4 Child SA.
- User-space ESP through strongSwan libipsec and the Windows VPN data channel.
- An editable list of this provider's existing Windows VPN profiles.
- Grouped basic, security, connection and network settings with contextual help.
- Full/split IPv4 routing, negotiated or custom DNS, and an optional local-subnet
  exclusion.
- Opt-in IPv4 MOBIKE, with physical-interface binding for the encrypted UDP
  transport and route/application-source checks after a network change.
- Proactive and peer-initiated IKE and Child SA rekeying without recreating the
  Windows channel. Rekey policy/status use separate versioned ABI extensions.
- A repository-owned PNG icon, generated multi-size assets and dynamic system
  light/dark theme resources.
- Command-line offline regressions and separate, explicitly invoked live-network
  acceptance tools.

This is not a production-ready VPN release. IPv6 tunneling, certificate/EAP
authentication, concurrent tunnels, proactive reauthentication and a system-wide
kill switch are not implemented. Full-tunnel mode captures and drops public IPv6
rather than allowing an IPv6 bypass; split mode does not capture unrelated IPv6.
A local-subnet exclusion can overlap a remote LAN, so configure it deliberately.
Deleting a profile does not yet remove an orphaned protected credential file.

## Build

Use a Windows x64 development machine with Git, Visual Studio C++ tools and a
Windows SDK containing C++/WinRT headers. Installing the MSIX also requires the
x64 Microsoft.VCLibs.140.00 framework. No C# or .NET Native build is required.

All third-party build dependencies are workspace-local. Scripts discover Visual
Studio and the SDK through the installed toolchain instead of fixed user or
drive paths. Autotools requires a checkout path without spaces, or an available
NTFS short path.

Run from the repository root in Windows PowerShell:

If Windows PowerShell blocks local scripts, invoke a child process with
`powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File` followed by the
script path and its arguments. This changes only that child process, not the
user or machine execution policy. Visual Studio's build command uses the same
process-scoped option.

```powershell
.\scripts\Initialize-Toolchain.ps1 -InstallPackages
.\scripts\Fetch-Upstream.ps1
.\scripts\Build-Core.ps1
.\scripts\Build.ps1
```

Downloads are verified against SHA-256 pins in `upstream.lock.json`. The core
build reapplies `scripts/strongswan-rekey-race.patch` idempotently. Plugin
constructor tables are generated during the build. Generated sources, the
toolchain and the extracted upstream tree are not committed.

For offline testing without a registered VCLibs framework, use the pinned
Microsoft desktop test forwarders:

```powershell
.\scripts\Initialize-TestRuntime.ps1
.\scripts\Build.ps1 -TestRuntimeDirectory build/test-runtime/package/runtimes/win-x64/native/release
```

The forwarders affect only the offline activation test process. They are not
installed and are never copied into the MSIX. This does not replace the runtime
required for an installed application.

`Build.ps1` produces an unsigned package in `dist/` and runs offline tests by
default. `-ToolsOnly` builds/runs test helpers without repackaging;
`-AcceptanceHooks` adds development-only fault/provisioning hooks, disabled in
normal builds. `-SkipTests` is available but is not used by CI.

### Local signing and installation

Signing is separate from building and is never performed by CI:

```powershell
.\scripts\Sign-Dev.ps1
.\scripts\Install-Signed.ps1
```

The publisher certificate must match the package manifest. A local development
certificate does not inherit strongSwan's signing identity. On another machine,
review and explicitly trust the intended development publisher before installing.
`Trust-DevCertificate.ps1` requires an administrator and targets TrustedPeople,
not Trusted Root Certification Authorities. Building and signing do not import
certificate trust or change system development policy.

Increment the manifest version before installing changed package contents over
an existing installation. Installation preserves application LocalState. Do not
install an acceptance build over an active VPN session.

## Configuration

The interface follows the first language in the Windows preferred-language
list. Simplified Chinese uses the `zh-Hans` resources; every other language,
including Traditional Chinese, uses English. There is no independent app
language setting. System language changes refresh labels, choices, help and
status text when reported by Windows or when the app returns to the foreground,
without discarding unsaved edits. Language settings that Windows applies only
after sign-in also require that system sign-in before the app can observe them.

Use the companion application to add or edit a connection. Its sidebar lists
only profiles owned by this VPN provider. Selecting a profile does not connect
or disconnect it. Saving checks provider ownership, disconnected status and
unchanged custom XML before updating the same Windows profile. Unsupported
custom XML stays read-only.

Use your own gateway, local identity, remote identity and PSK. Documentation
uses named placeholders such as `<VPN_GATEWAY>`, `<LOCAL_ID>` and
`<REMOTE_ID>`; no deployment addresses or credential values are published.
Do not replace placeholders in committed documentation with real values.

A blank PSK while editing retains the existing protected credential reference.
New PSKs are protected for the current user through DataProtectionProvider;
profile XML contains only an opaque credential reference. Diagnostic tools pass
secrets through anonymous stdin, not process arguments, environment variables
or plaintext temporary files. Never publish exported connection files.

| Setting | Supported choices / default |
| --- | --- |
| Authentication | Symmetric IKEv2 PSK |
| Identity type | FQDN or IPv4 for each peer |
| IKE proposal | AES-128/192/256 with SHA-256 and MODP2048; optional AES-256 with MODP3072 |
| ESP proposal | AES-128/192/256 with SHA-256; default AES-256, no ESP PFS |
| IKE fragmentation | Enabled when supported by both peers |
| MOBIKE | Disabled by default; IPv4 client network changes after peer negotiation |
| DPD idle interval | 0-300 seconds; default 20, zero disables active probing |
| NAT keepalive | 5-120 seconds; default 15 |
| First retransmission / retries | 1-10 seconds / 1-8; defaults 1 / 3, with backoff |
| IKE initiation attempts | 1-6; default 1, also bounded by the negotiation wait |
| Negotiation wait | 5-120 seconds; default 25 |
| Child SA hard lifetime | 300-172800 seconds; default 86400 |
| IKE rekey | Disabled, or 60-604800 seconds; default 14400 |
| Child rekey | Disabled, or 10-95% of hard lifetime; default 90% |
| Rekey random advance | 0-25%; default 5% |
| Gateway UDP port / MTU | 1-65535 / 576-1400; defaults 4500 / 1280 |
| IPv4 routing | Full tunnel or up to 32 canonical CIDRs; local exclusion on by default |
| DNS | Server-supplied, up to four custom IPv4 servers, or system DNS |

Server traffic selectors must allow the requested destinations. Split-mode DNS
servers receive host routes through the tunnel. Choosing system DNS can send
queries outside the VPN. Opening the editor never rewrites existing custom XML;
an explicit save writes the current schema.

### Windows VPN settings

App-created profiles enable `VpnPlugInProfile.RequireVpnClientAppUI`, allowing
Windows Settings to list and manage the connection. Disconnected legacy profiles
are repaired in place on application launch. Other providers and active sessions
are not modified. An already-open Settings process may need to be closed and
reopened to refresh its cached list.

The generic Windows Add VPN form does not collect this provider's explicit IKE
identities and PSK. Initial provisioning therefore still uses the companion
application; registration alone does not make the generic form sufficient.

## Continuous integration

`.github/workflows/ci.yml` runs on pushes, pull requests and manual dispatch:

- Ubuntu builds and runs the portable C++ contract tests, checks shell syntax
  and validates publication hygiene.
- Windows builds the pinned strongSwan source and its local patch, runs native
  mobility/rekey regressions, and builds/tests both production and acceptance
  MSIX configurations.
- Offline coverage includes profile parsing, ABI validation, activation,
  credential protection, recovery/evidence validation, UI styles and icon assets.
- Actions use immutable commit pins and read-only repository permissions.
  Dependabot proposes weekly action updates.
- Only offline build/test logs are uploaded, with limited retention. No signing
  secrets, app installation, trust imports, live VPN connections or automatic
  binary release are configured.

These checks do not prove connectivity to a real server or actual network
migration. Hosted workflow results are reported on the repository's Actions page.
Local test success is not a substitute for that result.

## Live acceptance

Live tests are opt-in and separate from CI. Use a dedicated test profile and a
private configuration under ignored `private/`. Never run them against another
person's connection or while relying on the same tunnel for remote control.
Acceptance-only provisioning presets and server helpers use example topology
and identities. Adapt them to a private test deployment before running live
checks; they are not ready-to-run settings for a particular network. See
[OpenWrt development helpers](../scripts/openwrt/README.md).

```powershell
.\scripts\Test-LocalVpn.ps1 -Action Status
.\scripts\Test-LocalVpn.ps1 -Action Run -ProfileName <TEST_PROFILE_NAME>
```

`Run` verifies fresh IKE/Child/channel state, bound Windows DNS and HTTPS traffic,
and increasing encrypted counters. It disconnects its own attempt and compares
network state afterward. `Connect` alone is not traffic acceptance.
`Get-VpnConnection` does not enumerate the application's private phonebook.

### MOBIKE

Enable MOBIKE on both peers and require negotiated `MOBIKE_SUPPORTED`.
The supported scope is IPv4 client path changes to the same reachable server
address and UDP port. A replacement login is not counted as migration.

`Prepare-MobikeAcceptance.ps1` prepares an owned test profile.
`Test-VpnMobike.ps1 -Mode Probe` tests same-network transport replacement only.
`-Mode Watch` requires a real physical path change, matching SA identity,
acknowledged updates, unchanged virtual address and renewed protected traffic.
The guarded full-tunnel helpers arm an independent 90-second disconnect process
before connecting a dedicated test VPN. Switch networks only after the readiness
file is written, wait for validation, then switch back without manual redial.

### Rekey

IKE and Child rekeys use `CREATE_CHILD_SA`, not a fresh authentication.
Default IKE rekey is four hours; Child rekey is 90% of its hard lifetime, with
up to 5% random advance. Peer-initiated rekeys remain supported when proactive
timers are disabled. Expired keys are not kept alive after a failed rekey.

`Test-NativeRekey.ps1`, `Invoke-WindowsRekeyAcceptance.ps1` and
`Complete-RekeyAcceptance.ps1` distinguish SPI/key replacement from redial.
They require matching server-side SA generations and bidirectional encrypted
counters. Server lab helpers must target an isolated owned test connection;
their rollback data contains credentials and must remain private.

### Lifecycle

`Test-VpnLifecycle.ps1` provides bounded idle, reconnect and real suspend/resume
tests. Fault injection requires an acceptance build and an expiring lease.
A resume result requires real Windows power events, not a timer pause.
Command-supervised redial is reported separately from same-SA recovery and is
not a claim of native Always On VPN behavior or indefinite uptime.

## Publishing and security

Read [CONTRIBUTING.md](../CONTRIBUTING.md) for clean-checkout checks and publishing,
and [SECURITY.md](../SECURITY.md) before sharing diagnostics. Private router backups,
exports, keys, certificates, phonebooks, toolchains, logs and generated packages
are excluded from the public source tree. The hygiene check also examines
tracked files, so adding a sensitive file forcibly will fail CI.

## Licensing

Original source, scripts, tests, documentation and the authorized icon are
**GPL-2.0-or-later**. Relevant strongSwan source notices are retained.
The OpenSSL 3-linked combined Windows binary must use **GPL-3.0-or-later**.
See [LICENSING.md](../LICENSING.md), [LICENSE](../LICENSE),
[GPL version 3](../LICENSES/GPL-3.0.txt) and
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

Binary redistribution requires the applicable notices and complete corresponding
source; an unsigned CI build is not a distribution-compliance audit.
No commercial VPN code, libraries or drivers are reused.

## References

- [Windows VPN APIs and sample](https://github.com/microsoft/UwpVpnPluginSample)
- [strongSwan rekeying](https://docs.strongswan.org/docs/latest/config/rekeying.html)
- [strongSwan Windows support](https://docs.strongswan.org/docs/latest/os/windows.html)
- [strongSwan user-space IPsec backend](https://docs.strongswan.org/docs/latest/plugins/kernel-libipsec.html)
