[CmdletBinding()]
param([string]$Root)
$ErrorActionPreference = 'Stop'
if (!$Root) { $Root = Split-Path -Parent $PSScriptRoot }
$Root = (Resolve-Path -LiteralPath $Root).Path
$sourceRelative = 'third_party/strongswan-6.1.0'
if (!(Test-Path -LiteralPath (Join-Path $Root $sourceRelative))) { throw 'Fetch the pinned upstream source first.' }
$git = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$patch = Join-Path $PSScriptRoot 'strongswan-rekey-race.patch'
$prefix = '--directory=' + $sourceRelative
$previous = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    $output = & $git -c core.autocrlf=false -C $Root apply $prefix --reverse --check $patch 2>&1
    $applied = $LASTEXITCODE -eq 0
} finally { $ErrorActionPreference = $previous }
if (!$applied) {
    & $git -c core.autocrlf=false -C $Root apply $prefix --check $patch
    if ($LASTEXITCODE) { throw 'The pinned Child SA checkout patch does not match this source.' }
    & $git -c core.autocrlf=false -C $Root apply $prefix $patch
    if ($LASTEXITCODE) { throw 'Could not apply the pinned Child SA checkout patch.' }
}
Write-Output 'Pinned strongSwan patch is applied; no index or global Git configuration was changed.'
