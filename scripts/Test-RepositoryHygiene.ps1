[CmdletBinding()]
param([string]$Root)
$ErrorActionPreference = 'Stop'
if (!$Root) { $Root = Split-Path -Parent $PSScriptRoot }

function Get-PublicationIssues([string]$RelativePath, [string]$Content = '') {
    $path = $RelativePath.Replace('\', '/')
    if ($path -match '(^|/)(?:private|build|dist|tools|third_party|\.vs|\.cache|\.codex|out|cmake-build-[^/]*)(/|$)') {
        'Private or generated directory'
    }
    if ($path -match '(?i)\.(?:pfx|p12|pem|key|ppk|cer|crt|pbk|tgb|secrets|log|dmp|pcap|pcapng|etl|msix|appx|apk|exe|dll|lib|a|so|dylib|nupkg|zip|7z|tar|gz|xz)$' -or
        ($path -match '(^|/)\.env(?:\.[^/]*)?$' -and $path -notmatch '(^|/)\.env\.example$')) {
        'Secret, local configuration or generated binary file'
    }
    if ($Content -match '-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----') { 'Private key material' }
    if ($Content -match '\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|(?:AKIA|ASIA)[A-Z0-9]{16})\b') {
        'Credential token pattern'
    }
    $assignments = [regex]::Matches($Content, '(?im)^\s*(?:psk|secret|password|passwd)\s*=\s*([^\r\n#]+)')
    foreach ($assignment in $assignments) {
        $rawValue = $assignment.Groups[1].Value.Trim()
        $isConfiguration = $path -match '(?i)\.(?:conf|ini|md|rst)$|(^|/)\.env(?:\.|$)'
        if (!$isConfiguration -and $rawValue -notmatch '^(?:L|u8|@)?["'']') { continue }
        $value = $rawValue.Trim([char]34, [char]39)
        if ($value -notmatch '^(?:<[^>]+>|\$[\w{].*|REDACTED|EXAMPLE_[A-Z_]+)$') {
            'Literal credential assignment'
            break
        }
    }
    if ($Content -match '(?is)<preshared(?:\s[^>]*)?>\s*[^<\s][^<]*</preshared>') {
        'Credential-bearing VPN export'
    }
    $isDocumentation = $path -match '(?i)\.(?:md|rst)$' -or $path -match '^docs/.*\.txt$'
    if ($isDocumentation) {
        if ($Content -match '[\u3400-\u4DBF\u4E00-\u9FFF\uF900-\uFAFF]') { 'Documentation must be in English' }
        if ($Content -match '(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])') {
            'Use named placeholders instead of IP addresses in documentation'
        }
        foreach ($candidate in [regex]::Matches($Content, '(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:./]*(?![\w:])')) {
            $address = $null
            if ([Net.IPAddress]::TryParse($candidate.Value.Split('/')[0], [ref]$address)) {
                'Use named placeholders instead of IP addresses in documentation'
                break
            }
        }
        if ($Content -match '(?i)[/\\](?:Users|home)[/\\][^\s/\\]+') { 'Personal filesystem path in documentation' }
    }
}

function Get-RepositoryCandidatePaths([string]$RepositoryRoot) {
    $git = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $records = & $git -c core.quotepath=false -C $RepositoryRoot ls-files --cached --others --exclude-standard -z
    if ($LASTEXITCODE) { throw 'Run the hygiene check inside an initialized Git repository.' }
    (($records -join "`n") -split "`0") | Where-Object { $_ } | Sort-Object -Unique
}

function Invoke-RepositoryHygiene([string]$RepositoryRoot) {
    $resolved = (Resolve-Path -LiteralPath $RepositoryRoot).Path
    $prefix = $resolved.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $findings = @()
    $paths = @(Get-RepositoryCandidatePaths $resolved)
    if (!$paths.Count) { throw 'No public repository candidates were found.' }
    foreach ($path in $paths) {
        $absolute = [IO.Path]::GetFullPath((Join-Path $resolved $path))
        if (!$absolute.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Repository path escapes the checkout.' }
        if (!(Test-Path -LiteralPath $absolute)) { continue }
        $item = Get-Item -LiteralPath $absolute -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            $findings += [pscustomobject]@{ Path = $path; Rule = 'Public files must not be symbolic links or junctions' }
            continue
        }
        $content = ''
        if ($item.Extension -notin @('.png', '.ico') -and $item.Length -le 2MB) {
            $content = [IO.File]::ReadAllText($absolute)
        } elseif ($item.Extension -notin @('.png', '.ico')) {
            $findings += [pscustomobject]@{ Path = $path; Rule = 'Non-image file exceeds the review size limit' }
        }
        foreach ($rule in @(Get-PublicationIssues $path $content)) {
            $findings += [pscustomobject]@{ Path = $path; Rule = $rule }
        }
    }
    if ($findings.Count) {
        foreach ($finding in $findings) { Write-Output ('FAIL {0}: {1}' -f $finding.Path, $finding.Rule) }
        throw ('Publication hygiene failed with {0} finding(s). Values are intentionally not printed.' -f $findings.Count)
    }
    Write-Output ('PASS publication hygiene: {0} public candidate files; ignored local data excluded.' -f $paths.Count)
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-RepositoryHygiene $Root }
