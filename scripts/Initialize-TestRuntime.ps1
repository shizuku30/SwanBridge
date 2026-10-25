[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $root 'build/test-runtime'
$package = Join-Path $destination 'Microsoft.VCRTForwarders.140.1.1.0.nupkg'
$lock = (Get-Content (Join-Path $root 'upstream.lock.json') -Raw -Encoding UTF8 | ConvertFrom-Json).testRuntime
$null = New-Item -ItemType Directory -Force -Path $destination
if (!(Test-Path -LiteralPath $package)) {
    Invoke-WebRequest -UseBasicParsing -Uri $lock.archive -OutFile $package
}
if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash -ne $lock.sha256) {
    throw 'Microsoft test-forwarder package SHA256 mismatch.'
}
$unpacked = Join-Path $destination 'package'
if (!(Test-Path -LiteralPath $unpacked)) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($package)
    try {
        $prefix = [IO.Path]::GetFullPath($unpacked) + [IO.Path]::DirectorySeparatorChar
        foreach ($entry in $archive.Entries) {
            $target = [IO.Path]::GetFullPath((Join-Path $unpacked $entry.FullName))
            if (!$target.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe test-runtime archive entry.' }
        }
    } finally { $archive.Dispose() }
    [IO.Compression.ZipFile]::ExtractToDirectory($package, $unpacked)
}
if (!(Test-Path (Join-Path $unpacked 'runtimes/win-x64/native/release/msvcp140_app.dll'))) {
    throw 'The verified package is missing its x64 test forwarder.'
}
Write-Output 'Prepared workspace-local desktop test forwarders. No app, certificate or runtime was installed.'
