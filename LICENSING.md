# Licensing

Original SwanBridge source code, build scripts, tests and documentation are
licensed under **GPL-2.0-or-later**, following the version-2-or-later notices in
the strongSwan sources used by this project. The complete GPL version 2 text is
in `LICENSE`. Copyright in original contributions belongs to their respective
contributors. There is no warranty.

Third-party files retain their original authors, copyright notices and licenses.
This project does not claim to own strongSwan, OpenSSL, Microsoft SDKs
or their trademarks. Existing per-file notices take precedence for those files.
See `THIRD_PARTY_NOTICES.md` and the notices copied alongside packaged binaries.

## OpenSSL 3 and the combined Windows binary

The Windows engine links OpenSSL 3, which uses Apache-2.0. Apache-2.0 is compatible
with GPL version 3, not GPL version 2 alone. The current combined Windows binary
must therefore be conveyed under **GPL-3.0-or-later**, exercising the "or later"
permission of the relevant GPL-2.0-or-later sources. The GPL version 3 text is in
`LICENSES/GPL-3.0.txt`. This does not erase or rewrite any upstream source notice.
No additional linking exception is assumed or invented for upstream code.

Before distributing a binary, review all included components, provide the
complete corresponding source and installation/build information required by
their licenses, and retain their notices. A pointer to an unpinned upstream
branch is not a substitute for the source corresponding to the actual binary.
CI validation is not a legal audit or permission to omit dependency sources.

References:

- [strongSwan licensing](https://www.strongswan.org/license.html)
- [GNU GPL version compatibility](https://www.gnu.org/licenses/gpl-faq.en.html#v2v3Compatibility)
- [Apache license compatibility](https://www.apache.org/foundation/license-faq.html#GPL)

## Artwork

The repository owner confirmed on 2026-10-25 that they have the right to
redistribute `package/Assets/SwanBridge.png` and authorize its distribution under
the project's GPL-2.0-or-later license. See `package/Assets/Source.md` for the
original file digest. This statement records the owner's authorization; it does
not claim that the strongSwan project supplied or endorsed the artwork.

## Certificates are not licenses

Open-source licensing does not grant access to an upstream publisher's signing
key or signing identity. Local development certificates and their trust are
machine-specific. CI does not export private keys, import trust certificates,
sign packages, or publish a release. Any future production-signing configuration
must be authorized separately and keep signing keys outside the repository.
