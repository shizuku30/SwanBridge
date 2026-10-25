[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-zA-Z0-9.-]+$')][string]$Router,
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (!$OutputDirectory) {
    $OutputDirectory = Join-Path $root ('private\router-migration-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Use a new migration directory.' }
$null = New-Item -ItemType Directory -Path $OutputDirectory
$directory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $directory /inheritance:r /grant:r ('*' + $sid + ':(OI)(CI)F') '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE) { throw 'Could not restrict the migration directory ACL.' }
$partial = Join-Path $directory 'router-work.tar.gz.partial'
$archive = Join-Path $directory 'router-work.tar.gz'
$p = [Diagnostics.Process]::new()
$p.StartInfo.FileName = 'ssh.exe'
$p.StartInfo.Arguments = '-T -o StrictHostKeyChecking=yes -o ConnectTimeout=6 root@' + $Router +
    ' "set -o pipefail; nice -n 15 tar -C / -czpf - root/swanbridge-build root/swanbridge-deploy etc/config/ipsec etc/apk/keys/swanbridge-25.12.pem"'
$p.StartInfo.UseShellExecute = $false
$p.StartInfo.CreateNoWindow = $false
$p.StartInfo.RedirectStandardOutput = $true
$file = [IO.File]::Open($partial, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $null = $p.Start()
    $copy = $p.StandardOutput.BaseStream.CopyToAsync($file)
    if (!$copy.Wait(1200000)) { $p.Kill(); throw 'Archive transfer timed out; remote files were not removed.' }
    $null = $copy.GetAwaiter().GetResult()
    $p.WaitForExit()
    if ($p.ExitCode) { throw 'SSH archive transfer failed; remote files were not removed.' }
    $file.Flush($true)
} finally { $file.Dispose(); $p.Dispose() }
Move-Item -LiteralPath $partial -Destination $archive
[pscustomobject]@{
    Archive = $archive
    Bytes = (Get-Item -LiteralPath $archive).Length
    SHA256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    RemoteDeleted = $false
    VerificationRequired = $true
} | ConvertTo-Json
