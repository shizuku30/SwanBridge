#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$VpnConfFile,
    [ValidateSet('ClientTimers','ServerControlled')][string]$Mode='ClientTimers',
    [ValidateRange(60,600)][int]$Seconds=210,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference='Stop'
$requestedOutput=$OutputDirectory
. (Join-Path $PSScriptRoot 'Test-LocalVpn.ps1')
$OutputDirectory=$requestedOutput
$null=New-Item -ItemType Directory -Path $OutputDirectory -Force
$OutputDirectory=(Resolve-Path -LiteralPath $OutputDirectory).Path
$inputText=Get-Content -LiteralPath $VpnConfFile -Raw -Encoding UTF8
$start=$inputText.IndexOf('<?xml')
if ($start -lt 0) { throw 'The supplied file does not contain VpnConf XML.' }
try { [xml]$source=$inputText.Substring($start) }
catch { throw 'Invalid VpnConf XML; input contents were not logged.' }
$ike=$source.tgbconfig.cfg_ikev2.cfg_connectionv2.cfg_ike_sa
if ($ike.authentication.type -ne 'preshared') { throw 'A supplied PSK configuration is required.' }
$remote=[string]($ike.identity|Where-Object location -eq remote).'#text'
$server=[string]$ike.server
if (!$remote -or !$server -or $remote -match '["\r\n]' -or $server -match '["\r\n]') { throw 'Invalid endpoint or identity.' }
$binary=Join-Path $root 'build/engine/SwanBridge.RekeyProbe.exe'
if (!(Test-Path $binary)) { throw 'Build the native rekey probe first.' }
$before=Get-NetworkSnapshot
Write-JsonFile $before (Join-Path $OutputDirectory 'network-before.json')
$ikeTime=0; $childPercent=0
if ($Mode -eq 'ClientTimers') { $ikeTime=90; $childPercent=20 }
$p=[Diagnostics.Process]::new()
$p.StartInfo=[Diagnostics.ProcessStartInfo]::new($binary,('"'+$server+'" swanbridge-rekey-acceptance "'+$remote+'" '+$Seconds+' '+$ikeTime+' '+$childPercent+' 0'))
$p.StartInfo.UseShellExecute=$false; $p.StartInfo.CreateNoWindow=$true
$p.StartInfo.RedirectStandardInput=$true; $p.StartInfo.RedirectStandardOutput=$true; $p.StartInfo.RedirectStandardError=$true
$result=[ordered]@{Outcome='ERROR';Accepted=$false;Mode=$Mode;WindowsDataChannelAccepted=$false;StartedAt=[DateTimeOffset]::Now.ToString('o')}
$startedProcess=$false
try {
    $null=$p.Start()
    $startedProcess=$true
    $stdout=$p.StandardOutput.ReadToEndAsync(); $stderr=$p.StandardError.ReadToEndAsync()
    $secret=[Text.Encoding]::UTF8.GetBytes(([string]$ike.authentication.preshared)+"`n")
    try { $p.StandardInput.BaseStream.Write($secret,0,$secret.Length) }
    finally { [Array]::Clear($secret,0,$secret.Length); $p.StandardInput.Close() }
    if (!$p.WaitForExit(($Seconds+45)*1000)) { $p.Kill(); $p.WaitForExit(); throw 'The rekey probe exceeded its deadline.' }
    $log=$stderr.GetAwaiter().GetResult()
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'engine.log'),$log,[Text.UTF8Encoding]::new($false))
    $raw=$stdout.GetAwaiter().GetResult()
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'samples.jsonl'),$raw,[Text.UTF8Encoding]::new($false))
    $samples=@($raw -split '\r?\n'|Where-Object {$_}|ForEach-Object {$_|ConvertFrom-Json})
    if ($samples.Count -lt 2) { throw 'No continuous native traffic evidence.' }
    $result.Before=$samples[0]; $result.After=$samples[-1]; $result.SampleCount=$samples.Count
    $failures=@($samples|Where-Object {!$_.Authenticated -or !$_.ChildSaUp -or !$_.DnsTrafficPassed -or $_.IkeEstablishments -ne 1 -or $_.ChildEstablishments -ne 1 -or $_.VirtualIPv4 -ne $samples[0].VirtualIPv4})
    $result.TrafficFailures=$result.After.TrafficFailures
    $result.NoReauthentication=($log -notmatch 'reauthenticat(ing|ion in)' -and @($samples|Where-Object {$_.IkeEstablishments -ne 1}).Count -eq 0)
    if ($log -match 'not found for rekey') { throw 'A rekey job was lost while its Child SA was being inherited.' }
    if ($Mode -eq 'ClientTimers' -and ($result.After.IkeRekeysCompleted -lt [Math]::Floor($Seconds/90) -or
        $result.After.ChildRekeysCompleted -lt [Math]::Floor($Seconds/60))) { throw 'A scheduled rekey cycle was skipped.' }
    if ($p.ExitCode -ne 0 -or $failures.Count -or !$result.NoReauthentication -or !$result.After.Final -or
        $result.After.IkeRekeysCompleted -lt 1 -or $result.After.ChildRekeysCompleted -lt 2) { throw 'Rekey counts, continuity or protected traffic did not pass.' }
    $result.ClientEvidencePassed=$true; $result.Outcome='CLIENT_REKEY_PASSED_SERVER_VERIFICATION_REQUIRED'
} catch { $result.Error=$_.Exception.Message }
finally {
    if ($startedProcess -and !$p.HasExited) { $p.Kill(); $p.WaitForExit() }
    $p.Dispose()
    $after=Get-NetworkSnapshot
    Write-JsonFile $after (Join-Path $OutputDirectory 'network-after.json')
    $result.NetworkDifference=Get-SnapshotDifference $before $after
    $result.NetworkUnchanged=Test-SnapshotUnchanged $result.NetworkDifference
    if (!$result.NetworkUnchanged) { $result.Outcome='NETWORK_STATE_CHANGED'; $result.ClientEvidencePassed=$false }
    $result.CompletedAt=[DateTimeOffset]::Now.ToString('o')
    Write-JsonFile $result (Join-Path $OutputDirectory 'result.json')
}
[pscustomobject]$result|Select-Object Outcome,Mode,ClientEvidencePassed,SampleCount,TrafficFailures,NoReauthentication,NetworkUnchanged,Error|ConvertTo-Json
if (!$result.ClientEvidencePassed) { exit 1 }
exit 2
