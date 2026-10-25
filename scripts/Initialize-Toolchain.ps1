[CmdletBinding()]
param([switch]$InstallPackages)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tools = Join-Path $root 'tools'
New-Item -ItemType Directory -Force -Path $tools | Out-Null
$archive = Join-Path $tools 'msys2-base-x86_64-20260927.tar.xz'
if (!(Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest -Uri 'https://repo.msys2.org/distrib/x86_64/msys2-base-x86_64-20260927.tar.xz' -OutFile $archive
}
$expected = (Get-Content (Join-Path $root 'upstream.lock.json') -Raw -Encoding UTF8 | ConvertFrom-Json).msys2Base.sha256
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected) {
    throw 'MSYS2 archive SHA256 does not match the pinned release.'
}
if (!(Test-Path -LiteralPath (Join-Path $tools 'msys64\usr\bin\bash.exe'))) {
    $entries = & tar -tf $archive
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect toolchain archive.' }
    foreach ($entry in $entries) {
        if ($entry -notmatch '^msys64(/|$)' -or $entry -match '(^|/)\.\.(/|$)' -or $entry.Contains('\')) {
            throw 'Unexpected toolchain archive path.'
        }
    }
    & tar -xf $archive -C $tools
    if ($LASTEXITCODE -ne 0) { throw 'Cannot extract toolchain.' }
}
Get-FileHash -LiteralPath $archive -Algorithm SHA256 | Select-Object Algorithm,Hash
if ($InstallPackages) {
    $shortRoot = (New-Object -ComObject Scripting.FileSystemObject).GetFolder($tools).ShortPath
    if ($shortRoot.Contains(' ')) { throw 'MSYS2 needs a toolchain location without spaces (or enabled short names).' }
    $env:MSYSTEM = 'MINGW64'
    $env:CHERE_INVOKING = '1'
    & (Join-Path $shortRoot 'msys64\usr\bin\bash.exe') --login -c 'pacman -Syu --noconfirm'
    if ($LASTEXITCODE -ne 0) { throw 'MSYS2 update stopped. Close its processes and rerun this script; do not perform a partial upgrade.' }
    & (Join-Path $shortRoot 'msys64\usr\bin\bash.exe') --login -c 'pacman -S --noconfirm --needed make mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl mingw-w64-x86_64-pkgconf mingw-w64-x86_64-python'
    if ($LASTEXITCODE -ne 0) { throw 'Toolchain package installation failed.' }
}
