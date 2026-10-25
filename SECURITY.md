# Security

SwanBridge is experimental VPN software. It is not a production security
assurance, a system-wide kill switch or a substitute for endpoint protection.
Review the supported scope and limitations in `README.md` before use.

## Reporting a vulnerability

Use the repository's private vulnerability reporting feature if its owner has
enabled it. Do not open a public issue containing a working exploit with private
configuration, credentials or details of an unpatched deployment. If private
reporting is unavailable, first request a private contact channel without
including sensitive details. There is no promised response-time SLA.

Include the package/source version, Windows version, expected behavior, a
minimal sanitized reproduction and relevant non-secret error codes. Distinguish
an offline regression from an installed-client or real-network observation.

## Sharing diagnostics

Keep connection exports, private keys, publisher certificates, router backups,
credential blobs, phonebooks, packet captures and raw acceptance logs private.
Network snapshots can reveal routes, IP addresses, DNS servers, hostnames,
identities, session identifiers and infrastructure topology even if they do not
contain a PSK. Never upload those files as public CI artifacts.

Before sharing an excerpt, replace deployment-specific values with consistent
named placeholders, remove secrets entirely, and inspect screenshots and command
history as well as text files. Do not paste a real secret as an example.
Documentation must remain in English and must not contain deployment IPs,
passwords or personal filesystem paths.

`.gitignore` and `Test-RepositoryHygiene.ps1` reduce accidental publication but
cannot guarantee that a file is safe. The CI check considers tracked files too;
an ignored file is not safe to commit forcibly. If a real credential is exposed,
revoke or rotate it promptly. Removing a file in a later commit does not remove
it from Git history, forks, caches or existing artifacts.

## Build and signing boundaries

Downloads use HTTPS and pinned hashes where recorded in `upstream.lock.json`.
GitHub Actions are pinned to immutable commits and run with read-only repository
permissions. Hosted CI does not access a deployment, connect a VPN, sign a
package, install an app, import certificate trust or publish a binary release.

Local signing keys must remain outside source control. Never export a private
publisher key for an issue, pull request or CI log. Trust changes and installed
application testing are explicit operator actions, separate from an offline
build. Open-source licensing does not transfer an upstream signing identity.
