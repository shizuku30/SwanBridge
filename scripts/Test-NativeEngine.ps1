#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VpnConfFile,
    [string]$OutputDirectory,
    [string]$EngineDirectory,
    [string]$RemoteIdentityOverride,
    [switch]$UseInvalidPsk,
    [switch]$RepeatConnection
)
$ErrorActionPreference = 'Stop'
if ($UseInvalidPsk -and $RepeatConnection) { throw 'Negative-PSK and reconnect probes must be run separately.' }
$requestedOutput = $OutputDirectory
. (Join-Path $PSScriptRoot 'Test-LocalVpn.ps1')
$OutputDirectory = $requestedOutput
$root = Split-Path -Parent $PSScriptRoot
if (!$OutputDirectory) {
    $OutputDirectory = Join-Path $root ('build\acceptance\engine-auth-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$inputText = Get-Content -LiteralPath $VpnConfFile -Raw
$start = $inputText.IndexOf('<?xml')
if ($start -lt 0) { throw 'The input file does not contain VpnConf XML.' }
[xml]$configuration = $inputText.Substring($start)
$ike = $configuration.tgbconfig.cfg_ikev2.cfg_connectionv2.cfg_ike_sa
if ($ike.authentication.type -ne 'preshared') { throw 'Only pre-shared key authentication is supported.' }
$local = [string]($ike.identity | Where-Object location -eq local).'#text'
$remote = [string]($ike.identity | Where-Object location -eq remote).'#text'
if ($RemoteIdentityOverride) { $remote = $RemoteIdentityOverride }
foreach ($value in @([string]$ike.server, $local, $remote)) {
    if (!$value -or $value -match '["\r\n]') { throw 'Invalid server or identity in input configuration.' }
}
if (!$EngineDirectory) { $EngineDirectory = Join-Path $root 'build\engine' }
$binary = Join-Path (Resolve-Path -LiteralPath $EngineDirectory).Path 'SwanBridge.EngineProbe.exe'
if (!(Test-Path -LiteralPath $binary)) { throw 'Run scripts\Build-Core.ps1 first.' }
$before = Get-NetworkSnapshot
Write-JsonFile $before (Join-Path $OutputDirectory 'before.json')
$process = [System.Diagnostics.Process]::new()
$process.StartInfo = [System.Diagnostics.ProcessStartInfo]::new($binary,
    ('"' + $ike.server + '" "' + $local + '" "' + $remote + '"' + $(if ($RepeatConnection) { ' --repeat' } else { '' })))
$process.StartInfo.UseShellExecute = $false
$process.StartInfo.CreateNoWindow = $true
$process.StartInfo.RedirectStandardInput = $true
$process.StartInfo.RedirectStandardOutput = $true
$process.StartInfo.RedirectStandardError = $true
$result = [ordered]@{ Outcome = 'ERROR'; ExpectedServerIdentity = $remote;
    WindowsDataChannelAccepted = $false; OutputDirectory = $OutputDirectory }
try {
    $null = $process.Start()
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $secret = $(if ($UseInvalidPsk) { [guid]::NewGuid().ToString('N') } else { [string]$ike.authentication.preshared })
    $secretBytes = [System.Text.Encoding]::UTF8.GetBytes($secret + "`n")
    try { $process.StandardInput.BaseStream.Write($secretBytes, 0, $secretBytes.Length) }
    finally { [Array]::Clear($secretBytes, 0, $secretBytes.Length) }
    $process.StandardInput.Close()
    if (!$process.WaitForExit($(if ($RepeatConnection) { 90000 } else { 45000 }))) {
        $process.Kill()
        $process.WaitForExit()
        throw 'Native engine probe exceeded its deadline.'
    }
    $result.ExitCode = $process.ExitCode
    $result.Log = $stderr.GetAwaiter().GetResult()
    $result.Protocol = $stdout.GetAwaiter().GetResult() | ConvertFrom-Json
    $result.Outcome = $(if ($result.ExitCode -eq 0) { 'PASS_NATIVE_PROTECTED_TRAFFIC' } else { 'PROTOCOL_OR_TRAFFIC_FAILED' })
    if ($RepeatConnection -and $result.ExitCode -eq 0) {
        if ($result.Protocol.CyclesCompleted -ne 2) { throw 'The helper did not verify both connection cycles.' }
        $result.Outcome = 'PASS_NATIVE_RECONNECT_AND_PROTECTED_TRAFFIC'
    }
    if ($UseInvalidPsk -and $result.ExitCode -eq 2 -and !$result.Protocol.Authenticated -and
        !$result.Protocol.ChildSaUp -and !$result.Protocol.VirtualIPv4 -and !$result.Protocol.EspTx -and
        $result.Log -match 'AUTHENTICATION_FAILED') {
        $result.Outcome = 'PASS_INVALID_PSK_REJECTED'
        $result.ExitCode = 0
    } elseif ($UseInvalidPsk) {
        $result.Outcome = 'INVALID_PSK_NOT_SAFELY_REJECTED'
        $result.ExitCode = 1
    }
} catch {
    $result.Error = $_.Exception.Message
    $result.ExitCode = 1
} finally {
    $process.Dispose()
    $after = Get-NetworkSnapshot
    Write-JsonFile $after (Join-Path $OutputDirectory 'after.json')
    $result.NetworkDifference = Get-SnapshotDifference $before $after
    $result.NetworkUnchanged = Test-SnapshotUnchanged $result.NetworkDifference
    if (!$result.NetworkUnchanged) { $result.Outcome = 'NETWORK_STATE_CHANGED'; $result.ExitCode = 1 }
    Write-JsonFile $result (Join-Path $OutputDirectory 'result.json')
}
$result | ConvertTo-Json -Depth 8
exit $result.ExitCode
