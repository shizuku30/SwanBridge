#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\Test-LocalVpn.ps1')

function Check([bool]$Condition, [string]$Description) {
    if (!$Condition) { throw ('FAIL ' + $Description) }
    Write-Output ('PASS ' + $Description)
}

$empty = [pscustomobject]@{ Adapters = @(); Routes = @(); Dns = @(); IKEEXT = @() }
$baseline = [pscustomobject]@{
    Adapters = @([pscustomobject]@{ Name = 'Test'; Status = 'Up' })
    Routes = @([pscustomobject]@{ DestinationPrefix = '0.0.0.0/0'; NextHop = '192.0.2.1' })
    Dns = @([pscustomobject]@{ InterfaceIndex = 1; ServerAddresses = @('192.0.2.53') })
    IKEEXT = @([pscustomobject]@{ Name = 'IKEEXT'; State = 'Stopped'; StartMode = 'Disabled' })
}
Check (Test-SnapshotUnchanged (Get-SnapshotDifference $empty $empty)) 'empty network snapshots compare safely'
Check (Test-SnapshotUnchanged (Get-SnapshotDifference $baseline $baseline)) 'unchanged network snapshot accepted'
Check (!(Test-SnapshotUnchanged (Get-SnapshotDifference $empty $baseline))) 'added network state detected'
Check (!(Test-SnapshotUnchanged (Get-SnapshotDifference $baseline $empty))) 'removed network state detected'

$changed = $baseline | ConvertTo-Json -Depth 6 | ConvertFrom-Json
$changed.Dns[0].ServerAddresses = @('192.0.2.54')
Check (!(Test-SnapshotUnchanged (Get-SnapshotDifference $baseline $changed))) 'DNS server changes detected'
$changed = $baseline | ConvertTo-Json -Depth 6 | ConvertFrom-Json
$changed.IKEEXT[0].StartMode = 'Auto'
Check (!(Test-SnapshotUnchanged (Get-SnapshotDifference $baseline $changed))) 'IKEEXT startup changes detected'

$shell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$result = Invoke-BoundedProcess $shell '-NoProfile -Command "exit 7"' 5
Check ($result.ExitCode -eq 7 -and !$result.TimedOut) 'native process exit codes preserved'
$result = Invoke-BoundedProcess $shell '-NoProfile -Command "Start-Sleep -Seconds 15"' 1
Check ($result.ExitCode -eq 124 -and $result.TimedOut) 'timed-out helper process stopped'

function Invoke-BoundedProcess([string]$FilePath, [string]$Arguments, [int]$Seconds) {
    [pscustomobject]@{ Arguments = $Arguments }
}
$testPhonebook = Join-Path $env:TEMP 'SwanBridge tests\rasphone.pbk'
$result = Invoke-RasControl 'Test profile' $testPhonebook
Check ($result.Arguments -eq ('"Test profile" "/phonebook:' + $testPhonebook + '"')) 'connect uses the explicit package phonebook'
$result = Invoke-RasControl 'Test profile' $testPhonebook -Disconnect
Check ($result.Arguments -eq '"Test profile" /disconnect') 'disconnect does not use the unsupported phonebook switch'

$script:diagnosticReads = 0
function Get-PackageDiagnostics([string]$FamilyName) {
    $script:diagnosticReads++
    [pscustomobject]@{
        LastEvent = $(if ($script:diagnosticReads -eq 1) { 'Connect' } else { 'Disconnect' })
        LastEventTime = [DateTimeOffset]::Now.ToString('o')
        LastError = 'SB1001'
    }
}
$diagnostics = Wait-FailureDiagnostics 'Test.Package' ([DateTimeOffset]::Now.AddSeconds(-1))
Check ($script:diagnosticReads -eq 2 -and $diagnostics.LastEvent -eq 'Disconnect') 'asynchronous disconnect callback is awaited'

[byte[]]$query = @(83,66)
[byte[]]$reply = @(83,66,129,128,0,1,0,1,0,0,0,0)
Check (Test-DnsProbeReply $query $reply $reply.Length) 'matching successful DNS response accepted'
Check (!(Test-DnsProbeReply $query $reply 11)) 'truncated DNS response rejected'
Check (!(Test-DnsProbeReply $query $reply 13)) 'DNS response length outside the buffer rejected'
$reply[0] = 0
Check (!(Test-DnsProbeReply $query $reply $reply.Length)) 'unrelated DNS transaction rejected'
$reply[0] = 83; $reply[2] = 1
Check (!(Test-DnsProbeReply $query $reply $reply.Length)) 'DNS query is not mistaken for a response'
$reply[2] = 129; $reply[3] = 131
Check (!(Test-DnsProbeReply $query $reply $reply.Length)) 'DNS error response rejected'
$reply[3] = 128; $reply[7] = 0
Check (!(Test-DnsProbeReply $query $reply $reply.Length)) 'empty DNS answer rejected'

$project = Split-Path -Parent $PSScriptRoot
$app = Get-Content -LiteralPath (Join-Path $project 'src\App.cpp') -Raw
$testCleanup=[regex]::Match($app,'(?s)fire_and_forget RemoveRekeyProfile\(\).*?(?=fire_and_forget PrepareMobikeProfile)')
Check ($testCleanup.Success -and $testCleanup.Value -match 'SwanBridge-Acceptance-Rekey' -and
    $testCleanup.Value -match 'VpnPluginPackageFamilyName\(\) != Package::Current\(\).Id\(\).FamilyName\(\)' -and
    $testCleanup.Value -match 'ConnectionStatus\(\) != VpnManagementConnectionStatus::Disconnected' -and
    $testCleanup.Value -match 'options.localId != L"swanbridge-rekey-acceptance"') 'acceptance cleanup is restricted to the disconnected, owned rekey test identity'
$productionApp=$app.Remove($testCleanup.Index,$testCleanup.Length)
Check ($app -notmatch 'RequireVpnClientAppUI\(false\)' -and
    ([regex]::Matches($app, 'profile\.RequireVpnClientAppUI\(true\)')).Count -eq 2) 'new and legacy app profiles opt into Windows VPN UI visibility'
Check ($app -match 'UpdateProfileFromObjectAsync\(profile\)' -and
    $productionApp -notmatch 'DeleteProfileAsync') 'visibility repair updates the existing profile without deleting credentials or recreating connections'
Check ($app -match 'profile\.VpnPluginPackageFamilyName\(\) != family' -and
    $app -match 'profile\.ConnectionStatus\(\) != VpnManagementConnectionStatus::Disconnected') 'visibility repair skips other providers and active connections'
Check ($app -match 'profile\.CustomConfiguration\(\) != loadedXml' -and
    $app -match 'co_await agent.GetProfilesAsync\(\)' -and $productionApp -notmatch 'DeleteProfileAsync') 'profile editing checks stale configuration and never deletes an existing connection'
Check ($app -match 'hstring reference = credentialReference' -and
    $app -match 'if \(!psk\.Password\(\)\.empty\(\)\)' -and
    $app -match 'if \(credentialFile && !profileAdded\)') 'blank PSK retains the protected reference and failed saves clean up only their new credential file'
$sourceFiles = @(Get-ChildItem -Path @((Join-Path $project 'src'), (Join-Path $project 'scripts'),
    (Join-Path $project 'tests'), (Join-Path $project 'package')) -Recurse -File |
    Where-Object { $_.Extension -in @('.cpp', '.c', '.h', '.ps1', '.sh', '.xml') })
$machinePaths = @($sourceFiles | Select-String -Pattern '(?<![A-Za-z0-9])[A-Za-z]:[\\/]|/[a-z]/Users/' |
    Where-Object { $_.Line -notmatch '^\s*#' })
Check ($machinePaths.Count -eq 0) 'source dependencies contain no fixed drive or user paths'
