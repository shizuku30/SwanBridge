#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$VpnConfFile,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^SwanBridge-Acceptance-[A-Za-z0-9_. -]+$')][string]$ProfileName
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$package = Get-AppxPackage -Name SwanBridge.Vpn
if (!$package) { throw 'SwanBridge.Vpn is not installed.' }
$state = Join-Path $env:LOCALAPPDATA ('Packages\' + $package.PackageFamilyName + '\LocalState')
$phonebook = Join-Path $state 'rasphone.pbk'
$selected = $false
$hex = [System.Text.StringBuilder]::new()
foreach ($line in Get-Content -LiteralPath $phonebook) {
    if ($line -match '^\[([^\]]+)\]$') { $selected = $Matches[1] -ceq $ProfileName }
    if ($selected -and $line -match '^ThirdPartyProfileInfo=([0-9a-fA-F]+)$') { $null = $hex.Append($Matches[1]) }
}
if (!$hex.Length -or $hex.Length % 2) { throw 'The selected acceptance profile contains no valid provider configuration.' }
$bytes = [byte[]]::new($hex.Length / 2)
for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.ToString($i * 2, 2), 16) }
$text = [System.Text.Encoding]::Unicode.GetString($bytes)
$match = [regex]::Match($text, '<SwanBridge\b[^>]*>.*?</SwanBridge>', 'Singleline')
if (!$match.Success) { throw 'SwanBridge configuration was not found in the selected profile.' }
[xml]$profile = $match.Value
$inputText = Get-Content -LiteralPath $VpnConfFile -Raw
$start = $inputText.IndexOf('<?xml')
if ($start -lt 0) { throw 'The supplied file contains no VpnConf XML.' }
[xml]$configuration = $inputText.Substring($start)
$ike = $configuration.tgbconfig.cfg_ikev2.cfg_connectionv2.cfg_ike_sa
$local = [string]($ike.identity | Where-Object location -eq local).'#text'
$remote = [string]($ike.identity | Where-Object location -eq remote).'#text'
if ($ike.authentication.type -ne 'preshared' -or !$ike.authentication.preshared -or
    $profile.SwanBridge.Ikev2.server -cne [string]$ike.server -or
    $profile.SwanBridge.Ikev2.localId -cne $local -or $profile.SwanBridge.Ikev2.remoteId -cne $remote) {
    throw 'Input authentication or gateway identities do not match the acceptance profile. Nothing was changed.'
}
$reference = ([guid]$profile.SwanBridge.Ikev2.credentialRef).ToString('B')
$target = Join-Path $state ('Credentials\' + $reference + '.bin')
if (!(Test-Path -LiteralPath $target)) { throw 'The profile credential file does not exist.' }
$helper = Join-Path $root 'build\CredentialProbe.exe'
if (!(Test-Path -LiteralPath $helper)) { throw 'Build the credential helper with scripts\Build.ps1 -ToolsOnly.' }
$temporary = $target + '.' + [guid]::NewGuid().ToString('N') + '.new'
$process = [System.Diagnostics.Process]::new()
$process.StartInfo = [System.Diagnostics.ProcessStartInfo]::new($helper, ('--protect-stdin "' + $temporary + '"'))
$process.StartInfo.UseShellExecute = $false
$process.StartInfo.CreateNoWindow = $true
$process.StartInfo.RedirectStandardInput = $true
$process.StartInfo.RedirectStandardOutput = $true
$process.StartInfo.RedirectStandardError = $true
try {
    $null = $process.Start()
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $secretBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$ike.authentication.preshared + "`n")
    try { $process.StandardInput.BaseStream.Write($secretBytes, 0, $secretBytes.Length) }
    finally { [Array]::Clear($secretBytes, 0, $secretBytes.Length) }
    $process.StandardInput.Close()
    if (!$process.WaitForExit(15000)) { $process.Kill(); $process.WaitForExit(); throw 'Credential protection timed out.' }
    if ($process.ExitCode -ne 0) { throw ('Credential protection failed: ' + $stderr.GetAwaiter().GetResult()) }
    $backup = Join-Path $root ('build\acceptance\credential-backups\' + [guid]::NewGuid().ToString('N') + '.bin')
    $null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $backup)
    [System.IO.File]::Replace($temporary, $target, $backup)
    Write-Output 'Acceptance credential updated using DPAPI-NG LOCAL=user. Only encrypted blobs were written.'
} finally {
    $process.Dispose()
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
}
