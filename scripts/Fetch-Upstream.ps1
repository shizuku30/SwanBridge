[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $root 'third_party'
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$archive = Join-Path $destination 'strongswan-6.1.0.tar.gz'
if (!(Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest -Uri 'https://download.strongswan.org/strongswan-6.1.0.tar.gz' -OutFile $archive
}
$expected = 'D9484EEA319481BDA86F992FA69CBDBDD9C0D6F8B9A4BD793A7DF45C0760D963'
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected) {
    throw 'strongSwan archive SHA256 does not match the pinned release.'
}
$entries = & tar -tf $archive
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect upstream archive.' }
foreach ($entry in $entries) {
    if ($entry -notmatch '^strongswan-6\.1\.0(/|$)' -or $entry -match '(^|/)\.\.(/|$)' -or $entry.Contains('\')) {
        throw 'Unexpected upstream archive path.'
    }
}
if (!(Test-Path -LiteralPath (Join-Path $destination 'strongswan-6.1.0'))) {
    & tar -xf $archive -C $destination
    if ($LASTEXITCODE -ne 0) { throw 'Cannot extract upstream source.' }
}
Get-FileHash -LiteralPath $archive -Algorithm SHA256 | Select-Object Algorithm,Hash,Path
Write-Output 'Source extracted from the official HTTPS release endpoint. No code was executed.'
