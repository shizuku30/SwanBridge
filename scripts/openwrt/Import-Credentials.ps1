#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$VpnConfFile,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-zA-Z0-9.-]+$')][string]$Router,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ExpectedLocalId,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ExpectedRemoteId,
    [ValidatePattern('^/tmp/swanbridge-[a-zA-Z0-9._-]+$')][string]$RemoteDirectory = '/tmp/swanbridge-deploy'
)
$ErrorActionPreference = 'Stop'
$text = Get-Content -LiteralPath $VpnConfFile -Raw
$start = $text.IndexOf('<?xml')
if ($start -lt 0) { throw 'Expected original VpnConf XML.' }
[xml]$document = $text.Substring($start)
$ike = $document.tgbconfig.cfg_ikev2.cfg_connectionv2.cfg_ike_sa
$local = [string]($ike.identity | Where-Object location -eq local).'#text'
$remote = [string]($ike.identity | Where-Object location -eq remote).'#text'
if ($ike.authentication.type -ne 'preshared' -or $local.TrimStart('@') -ne $ExpectedLocalId.TrimStart('@') -or
    $remote -ne $ExpectedRemoteId -or !$ike.authentication.preshared) {
    throw 'Source authentication or identities differ; nothing imported.'
}
$bytes = [Text.Encoding]::UTF8.GetBytes([string]$ike.authentication.preshared)
$p = [Diagnostics.Process]::new()
$p.StartInfo.FileName = 'ssh.exe'
$p.StartInfo.Arguments = '-T -o StrictHostKeyChecking=yes -o ConnectTimeout=6 root@' + $Router +
    ' "cd ' + $RemoteDirectory + ' && umask 077 && ucode Import-Credentials.uc"'
$p.StartInfo.UseShellExecute = $false
$p.StartInfo.CreateNoWindow = $false
$p.StartInfo.RedirectStandardInput = $true
try {
    $secret = '0x' + ([BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
    $payload = @{local_id=('@'+$local.TrimStart('@')); server_id=$remote; server_host=[string]$ike.server; psk=$secret} | ConvertTo-Json -Compress
    $null = $p.Start()
    $p.StandardInput.Write($payload)
    $p.StandardInput.Close()
    if (!$p.WaitForExit(90000)) { $p.Kill(); throw 'Credential import timed out.' }
    if ($p.ExitCode) { throw 'SSH credential import failed.' }
} finally {
    [Array]::Clear($bytes, 0, $bytes.Length)
    $secret = $null; $payload = $null; $document = $null; $text = $null
    $p.Dispose()
}
