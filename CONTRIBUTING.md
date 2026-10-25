# Contributing

## Scope

Keep changes focused and retain the native Windows UWP provider architecture.
Do not add dependencies on another VPN product or a fixed developer-machine
path. Preserve upstream notices and record dependency changes in
`upstream.lock.json` and `THIRD_PARTY_NOTICES.md`.

Contributions to original project files are provided under GPL-2.0-or-later.
Do not contribute code, images or configuration that you cannot redistribute.
Third-party code keeps its own applicable license and attribution.

## Local checks

Initialize or clone a Git repository before running publication checks; they use
Git's tracked and non-ignored file lists instead of scanning private build data.
Run from the repository root:

```powershell
.\scripts\Test-RepositoryHygiene.ps1
.\tests\RepositoryHygieneTests.ps1
.\tests\PublicationTests.ps1
```

The portable contract tests need CMake and a C++20 compiler:

```sh
cmake -S . -B build/contracts -DCMAKE_BUILD_TYPE=Release
cmake --build build/contracts --config Release
ctest --test-dir build/contracts -C Release --output-on-failure
```

For the Windows engine and MSIX, follow the build commands in `README.md`.
Run both normal and `-AcceptanceHooks` builds when changing their shared code.
Offline tests never substitute for real traffic, MOBIKE, suspend or rekey
acceptance. Live tests require separate authorization and private configuration.

## Documentation and examples

Keep UI translations in the matching `package/Strings/en-US/Resources.resw` and
`package/Strings/zh-Hans/Resources.resw` catalogs. Preserve resource keys and
format arguments in both. Run `tests/LocalizationTests.ps1` and the portable
language-policy tests after changing translations or language selection.

Write public documentation in English. Use named placeholders such as
`<VPN_GATEWAY>`, `<LOCAL_ID>`, `<REMOTE_ID>` and `<TEST_PROFILE_NAME>` rather than
deployment addresses, hostnames, usernames or credential values. Never paste
real connection exports, router output or unredacted screenshots into a document
or issue. Supply secrets only through the intended protected input flow.

The repository hygiene check rejects private/generated paths, credential-like
files, selected secret patterns and IP literals in documentation. It is a guard
against accidents, not a complete secret detector. Review every staged diff.

## Prepare a public repository

Generated data and machine-local files must remain ignored. In particular, do
not use `git add --force` for private configurations, toolchains, certificates,
connection exports, phonebooks, build logs or packages.

Before the first commit or push:

```sh
git status --short --untracked-files=all
git diff --check
git diff --cached --check
git diff --cached --stat
```

Review the staged content locally, rerun the hygiene check, then commit and add
the intended GitHub remote. Do not put access tokens in the remote URL. This
project does not assume a repository owner or create a remote automatically.

The workflow runs with no repository secrets. Protect the default branch and
require its checks after the first successful hosted run. CI uploads only
offline test logs, not installable releases. A future binary release needs a
separate signing and corresponding-source plan as described in `LICENSING.md`.
