#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\Test-VpnLifecycle.ps1')

function Check([bool]$Condition, [string]$Description) {
    if (!$Condition) { throw ('FAIL '+$Description) }
    Write-Output ('PASS '+$Description)
}

$context = [pscustomobject]@{ Family='Test.Package'; ProfileName='SwanBridge-Acceptance-fixture'; Phonebook=(Join-Path $env:TEMP 'SwanBridge-fixture.pbk') }
$script:reads = 0
function Get-PackageDiagnostics([string]$FamilyName) {
    $script:reads++
    [pscustomobject]@{ EngineRunning=($script:reads -eq 1); ChannelUp=($script:reads -eq 1) }
}
$d=Wait-EngineStopped $context.Family 2
Check ($script:reads -eq 2 -and !$d.EngineRunning) 'lifecycle cleanup waits for native shutdown'

function Invoke-RasControl([string]$Name, [string]$Phonebook, [switch]$Disconnect) {
    if ($Name -ne $context.ProfileName -or $Phonebook -ne $context.Phonebook) { throw 'Wrong acceptance profile selected.' }
    [pscustomobject]@{ ExitCode=0; Output='fixture' }
}
$script:valid = $true
function Get-PackageDiagnostics([string]$FamilyName) {
    [pscustomobject]@{ ChannelUp=$script:valid; Authenticated=$script:valid; ChildSaUp=$script:valid;
        SessionId='fixture-session'; ConnectedAt=[DateTimeOffset]::Now.AddSeconds(1).ToString('o') }
}
$d=Connect-LifecycleSession $context
Check ($d.SessionId -eq 'fixture-session') 'freshly authenticated lifecycle connection accepted'
$script:valid=$false
$rejected=$false
try { $null=Connect-LifecycleSession $context } catch { $rejected=$true }
Check $rejected 'RAS success without authenticated Child SA rejected'
$script:valid=$true
$script:trafficCalls=0
function Test-WindowsVpnTraffic([string]$VirtualIPv4) { $script:trafficCalls++; throw 'Unexpected real traffic call.' }
$rejected=$false
try { $null=Test-LifecycleTraffic $context 'different-session' } catch { $rejected=$true }
Check ($rejected -and $script:trafficCalls -eq 0) 'unexpected soak reconnection rejected before traffic'
$script:valid=$false
$rejected=$false
try { $null=Test-LifecycleTraffic $context '' } catch { $rejected=$true }
Check ($rejected -and $script:trafficCalls -eq 0) 'dead Child SA cannot pass lifecycle traffic acceptance'

$script:disconnects=0
function Disconnect-LifecycleSession($Context) { $script:disconnects++; [pscustomobject]@{ EngineRunning=$false } }
function Connect-LifecycleSession($Context) { [pscustomobject]@{ SessionId='new-session' } }
function Test-LifecycleTraffic($Context,[string]$ExpectedSession) { [pscustomobject]@{ SessionId=$ExpectedSession } }
$repaired=Repair-LifecycleSession $context
Check ($repaired.Mode -eq 'CommandSupervisorRedial' -and $repaired.Attempts -eq 1 -and $script:disconnects -eq 1) 'command redial is identified separately from native automatic recovery'
Check ($repaired.Sample.SessionId -eq 'new-session') 'recovery verifies traffic on the fresh session'

$script:sleepAt=Get-Date
$script:wakeAt=$script:sleepAt.AddSeconds(90)
$script:includeWake=$true
function Get-WinEvent($FilterHashtable, $ErrorAction) {
    if ($FilterHashtable.Id -eq 42) {
        $event=[pscustomobject]@{ TimeCreated=$script:sleepAt; RecordId=100 }
        $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
            '<Event><EventData><Data Name="TargetState">5</Data></EventData></Event>'
        }
        return $event
    }
    if ($script:includeWake) { [pscustomobject]@{ TimeCreated=$script:wakeAt; RecordId=101 } }
}
$evidence=Get-SuspendEvidence $script:sleepAt.AddSeconds(-1)
Check ($evidence.Seconds -eq 90 -and $evidence.TargetState -eq '5') 'hibernate evidence requires paired operating-system events'
$script:includeWake=$false
Check ($null -eq (Get-SuspendEvidence $script:sleepAt)) 'elapsed time alone cannot pass real resume acceptance'
$script:includeWake=$true; $script:wakeAt=$script:sleepAt.AddSeconds(-1)
Check ($null -eq (Get-SuspendEvidence $script:sleepAt)) 'out-of-order resume events rejected'

$script:wakeAt=$script:sleepAt.AddSeconds(70)
function Get-WinEvent($FilterHashtable, $ErrorAction) {
    $event=[pscustomobject]@{ TimeCreated=$script:sleepAt; RecordId=100 }
    if ($FilterHashtable.Id -eq 42) {
        $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
            '<Event><EventData><Data Name="TargetState">5</Data></EventData></Event>'
        }
    } else {
        $event.TimeCreated=$script:wakeAt; $event.RecordId=101
        $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
            '<Event><EventData><Data Name="SleepTime">'+$script:sleepAt.ToUniversalTime().ToString('o')+
            '</Data><Data Name="WakeTime">'+$script:sleepAt.AddSeconds(90).ToUniversalTime().ToString('o')+
            '</Data></EventData></Event>'
        }
    }
    return $event
}
$evidence=Get-SuspendEvidence $script:sleepAt.AddSeconds(-1)
Check ($evidence.Seconds -eq 90 -and $evidence.TimingSource -eq 'PowerTroubleshooterPayload') 'resume duration uses OS payload timestamps instead of delayed event writes'
Check ($null -eq (Get-SuspendEvidence $script:sleepAt.AddMinutes(2))) 'an old suspend pair cannot satisfy a newly armed test'
