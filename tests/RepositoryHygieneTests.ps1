$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/Test-RepositoryHygiene.ps1')

function Check([bool]$Condition, [string]$Description) {
    if (!$Condition) { throw ('FAIL ' + $Description) }
    Write-Output ('PASS ' + $Description)
}
foreach ($path in @('private/router.json', 'build/result.json', 'dist/package.msix', 'tools/runtime.dll', 'third_party/source.c', 'nested/private/config')) {
    Check (@(Get-PublicationIssues $path).Count -gt 0) ('excluded directory detected: ' + $path)
}
foreach ($path in @('credential.pfx', 'profile.pbk', 'export.tgb', '.env', '.env.local', 'key.pem', 'engine.dll', 'trace.log', 'traffic.pcapng', 'events.etl', 'backup.7z')) {
    Check (@(Get-PublicationIssues $path).Count -gt 0) ('private or generated file detected: ' + $path)
}
Check (@(Get-PublicationIssues '.env.example').Count -eq 0) 'unpopulated example environment file is allowed'
Check (@(Get-PublicationIssues 'src/Engine.c' 'const char *name = "engine";').Count -eq 0) 'ordinary source is allowed'
Check (@(Get-PublicationIssues 'src/App.cpp' 'psk = PasswordBox();').Count -eq 0) 'credential field construction is not mistaken for a literal secret'
Check (@(Get-PublicationIssues 'src/fixture.cpp' 'psk = "fixture-value";').Count -gt 0) 'quoted credentials in source are detected'
$privateHeader = ('-----BEGIN ' + 'PRIVATE KEY-----')
Check (@(Get-PublicationIssues 'fixture.txt' $privateHeader).Count -gt 0) 'private key detected without printing its contents'
$token = ('gh' + 'p_' + ('A' * 36))
Check (@(Get-PublicationIssues 'fixture.json' $token).Count -gt 0) 'credential token pattern detected'
$literal = ('pass' + 'word = fixture-value')
Check (@(Get-PublicationIssues 'config.conf' $literal).Count -gt 0) 'literal credential assignment detected'
Check (@(Get-PublicationIssues 'config.conf' ('secret = ' + '$value')).Count -eq 0) 'variable references are not treated as embedded secrets'
$sample = 'secret = "Isolated-VM-test-only-not-a-production-secret"'
Check (@(Get-PublicationIssues 'scripts/openwrt/lab/server.conf' $sample).Count -eq 0) 'isolated lab sample is narrowly allowlisted'
Check (@(Get-PublicationIssues 'other.conf' $sample).Count -gt 0) 'lab exception cannot apply to other files'
$export = '<pre' + 'shared>fixture-value</pre' + 'shared>'
Check (@(Get-PublicationIssues 'fixture.xml' $export).Count -gt 0) 'credential-bearing export detected'
$ipv4 = '192' + '.0.2.1'
$ipv6 = '2001' + ':db8::1'
Check (@(Get-PublicationIssues 'README.md' $ipv4).Count -gt 0) 'documentation uses placeholders rather than IPv4 addresses'
Check (@(Get-PublicationIssues 'docs/guide.md' $ipv6).Count -gt 0) 'documentation uses placeholders rather than IPv6 addresses'
Check (@(Get-PublicationIssues 'README.md' ([string][char]0x4E2D)).Count -gt 0) 'non-English documentation is detected'
Check (@(Get-PublicationIssues 'README.md' 'Release v0.1.0.45 uses <VPN_GATEWAY>.').Count -eq 0) 'version numbers and named placeholders are allowed'
Check (@(Get-PublicationIssues 'src/test.cpp' $ipv4).Count -eq 0) 'synthetic test addresses do not become documentation violations'

$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$fixture = Join-Path $temporaryBase ('SwanBridge-Publication-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path (Join-Path $fixture 'private')
try {
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText((Join-Path $fixture '.gitignore'), "/private/`n", $utf8)
    [IO.File]::WriteAllText((Join-Path $fixture 'README.md'), 'Fixture uses <VPN_GATEWAY>.', $utf8)
    [IO.File]::WriteAllText((Join-Path $fixture 'private/fixture.conf'), $literal, $utf8)
    $git = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    & $git -C $fixture init --quiet
    if ($LASTEXITCODE) { throw 'Cannot initialize hygiene fixture repository' }
    $candidates = @(Get-RepositoryCandidatePaths $fixture)
    Check ('README.md' -in $candidates -and 'private/fixture.conf' -notin $candidates) 'public candidates honor Git ignore rules'
    & $git -C $fixture add --force private/fixture.conf
    if ($LASTEXITCODE) { throw 'Cannot stage fixture' }
    Check ('private/fixture.conf' -in @(Get-RepositoryCandidatePaths $fixture)) 'forcibly tracked private files are still scanned'
    $rejected = $false
    try { $null = Invoke-RepositoryHygiene $fixture } catch { $rejected = $_.Exception.Message -match 'Publication hygiene failed' }
    Check $rejected 'integration check rejects a forcibly tracked private credential file'
} finally {
    $resolvedFixture = [IO.Path]::GetFullPath($fixture)
    $allowedPrefix = $temporaryBase.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (!$resolvedFixture.StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $resolvedFixture) -notmatch '^SwanBridge-Publication-[a-f0-9]{32}$') {
        throw 'Refusing unsafe fixture cleanup path'
    }
    Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
}
