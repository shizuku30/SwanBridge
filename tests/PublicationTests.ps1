param([switch]$CheckLayout)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
function Read([string]$Path) { Get-Content -LiteralPath (Join-Path $root $Path) -Raw -Encoding UTF8 }
function Check([bool]$Condition, [string]$Description) {
    if (!$Condition) { throw ('FAIL ' + $Description) }
    Write-Output ('PASS ' + $Description)
}
$license = Read 'LICENSE'
$gpl3 = Read 'LICENSES/GPL-3.0.txt'
Check ($license.Length -gt 17000 -and $license -match 'Version 2, June 1991' -and $license -match 'END OF TERMS AND CONDITIONS') 'complete upstream GPLv2 license is present'
Check ($gpl3.Length -gt 30000 -and $gpl3 -match 'Version 3, 29 June 2007' -and $gpl3 -match 'END OF TERMS AND CONDITIONS') 'GPLv3 license for the combined binary is present'
Check ((Read 'LICENSING.md') -match 'GPL-2.0-or-later' -and (Read 'LICENSING.md') -match 'GPL-3.0-or-later') 'source and OpenSSL-linked binary licensing are distinguished'
Check ((Read 'package/Assets/Source.md') -match 'redistribution rights') 'artwork authorization is recorded'
foreach ($document in @('README.md', 'CONTRIBUTING.md', 'SECURITY.md', 'THIRD_PARTY_NOTICES.md')) {
    Check (Test-Path -LiteralPath (Join-Path $root $document)) ('publication documentation exists: ' + $document)
}
$workflow = Read '.github/workflows/ci.yml'
$actions = [regex]::Matches($workflow, '(?m)^\s*-?\s*uses:\s*([^\s#]+)')
Check ($actions.Count -ge 3) 'CI actions are declared'
foreach ($action in $actions) {
    Check ($action.Groups[1].Value -match '^[\w.-]+/[\w./-]+@[a-f0-9]{40}$') 'each CI action is pinned to an immutable commit'
}
Check ($workflow -match 'permissions:\s*\n\s*contents: read' -and $workflow -notmatch 'write-all|pull_request_target|secrets\.') 'CI uses read-only permissions without a secret-bearing PR trigger'
Check ($workflow -notmatch 'Sign-Dev|Trust-Dev|Install-Signed|Test-LocalVpn|Test-NativeEngine|Test-VpnLifecycle|Test-VpnMobike') 'CI does not sign, install, import trust or connect a VPN'
Check ($workflow -match 'path: build/ci/\*\.log' -and $workflow -notmatch 'path:\s*(?:dist|build/layout|private)') 'CI uploads offline logs only, not binaries or private data'
Check ($workflow -match 'PublicationTests.ps1 -CheckLayout') 'Windows CI checks the freshly built package notices'
$build = Read 'scripts/Build.ps1'
$publicFiles = @(& git -c core.quotepath=false -C $root ls-files --cached --others --exclude-standard)
if ($LASTEXITCODE) { throw 'Cannot inspect public repository files.' }
Check (@($publicFiles | Where-Object { $_ -match '^scripts/openwrt/|^tests/OpenClashPolicyTests\.ps1$|^scripts/Test-OpenWrtVpnTraffic\.ps1$' }).Count -eq 0) 'public source excludes server deployment and router policy tools'
foreach ($clientFile in @('scripts/Build-Core.ps1', 'scripts/build-core.sh', 'scripts/strongswan-rekey-race.patch', 'upstream.lock.json',
    'src/engine/Engine.c', 'scripts/Test-VpnMobike.ps1', 'scripts/Test-NativeRekey.ps1', 'scripts/Test-WindowsRekey.ps1', 'scripts/Test-SplitVpnTraffic.ps1')) {
    Check ($clientFile -in $publicFiles) ('client engine and acceptance tool remains public: ' + $clientFile)
}
foreach ($test in [regex]::Matches($build, "'([A-Za-z]+Tests\.ps1)'")) {
    Check (('tests/' + $test.Groups[1].Value) -in $publicFiles) ('offline build test exists in public source: ' + $test.Groups[1].Value)
}
Check ($build -match 'IsPathRooted\(\$TestRuntimeDirectory\)' -and $build -match 'finally \{ \$env:PATH = \$oldPath \}') 'desktop test forwarders are relative and PATH changes are scoped'
Check ($build -notmatch 'Copy-Item[^\r\n]*(?:runtimePath|test-runtime)') 'test forwarders are never copied into the MSIX'
Check ((Read 'scripts/Apply-CorePatches.ps1') -match '--directory=' -and (Read 'scripts/Build-Core.ps1') -match 'Apply-CorePatches.ps1') 'upstream patch application works from the checkout root'
$lock = Read 'upstream.lock.json' | ConvertFrom-Json
foreach ($dependency in @($lock.strongswan, $lock.msys2Base, $lock.testRuntime)) {
    Check ($dependency.archive -match '^https://' -and $dependency.sha256 -match '^[a-f0-9]{64}$') 'downloaded source and test dependencies have HTTPS and SHA256 pins'
}
$layout = Join-Path $root 'build/layout'
if ($CheckLayout) {
    Check (Test-Path -LiteralPath $layout) 'requested package layout exists'
    foreach ($notice in @('LICENSE', 'LICENSING.md', 'THIRD_PARTY_NOTICES.md', 'COPYING.strongswan', 'licenses/GPL-3.0.txt', 'licenses/openssl/LICENSE', 'licenses/libgcc/COPYING.RUNTIME')) {
        Check (Test-Path -LiteralPath (Join-Path $layout $notice)) ('package preserves license notice: ' + $notice)
    }
    Check (!(Test-Path -LiteralPath (Join-Path $layout 'msvcp140_app.dll'))) 'desktop test forwarders are absent from the package layout'
}
