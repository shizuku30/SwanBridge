#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(30,600)][int]$GuardSeconds=90,
    [ValidateSet('SwanBridge-Acceptance-MOBIKE','SwanBridge-Acceptance-Rekey')][string]$ProfileName='SwanBridge-Acceptance-MOBIKE',
    [Parameter(Mandatory=$true)][string]$GuardDirectory
)
$ErrorActionPreference='Stop'
$requestedProfile=$ProfileName
. (Join-Path $PSScriptRoot 'Test-LocalVpn.ps1')
$family='SwanBridge.Vpn_sbb2y36yht658'
$profile=$requestedProfile
$guardPath=(Resolve-Path -LiteralPath $GuardDirectory).Path
$rasPath=Join-Path $env:WINDIR 'System32\rasdial.exe'
$result=[ordered]@{ StartedAt=[DateTimeOffset]::Now.ToString('o'); ProfileName=$profile; SessionId=$null; Disconnected=$false }
try {
    $initial=Invoke-BoundedProcess $rasPath '' 5
    if ($initial.ExitCode -ne 0 -or $initial.Output.Contains($profile)) {
        throw 'Start the guard before connecting the dedicated test VPN.'
    }
    $deadline=[DateTimeOffset]::Now.AddSeconds($GuardSeconds)
    Write-JsonFile ([ordered]@{ Stage='GuardArmed'; GuardPid=$PID; ProfileName=$profile; Deadline=$deadline.ToString('o') }) (Join-Path $guardPath 'guard-ready.json')
    do {
        Start-Sleep -Seconds 1
        $status=Invoke-BoundedProcess $rasPath '' 5
        if ($status.ExitCode -eq 0 -and $status.Output.Contains($profile) -and !$result.SessionId) {
            $diagnostics=Get-PackageDiagnostics $family
            if ($diagnostics.ChannelUp -and $diagnostics.SessionId) { $result.SessionId=$diagnostics.SessionId }
        }
    } while ([DateTimeOffset]::Now -lt $deadline)
    $status=Invoke-BoundedProcess $rasPath '' 5
    if ($status.ExitCode -eq 0 -and $status.Output.Contains($profile)) {
        $diagnostics=Get-PackageDiagnostics $family
        if (!$result.SessionId -or $diagnostics.SessionId -eq $result.SessionId) {
            $disconnect=Invoke-RasControl $profile '' -Disconnect
            $result.DisconnectExitCode=$disconnect.ExitCode
            $result.Disconnected=$disconnect.ExitCode -eq 0
        } else { $result.Skipped='A different session replaced the guarded test connection.' }
    } else { $result.Skipped='The test VPN was already disconnected.' }
} catch { $result.Error=$_.Exception.Message }
finally {
    $result.CompletedAt=[DateTimeOffset]::Now.ToString('o')
    Write-JsonFile $result (Join-Path $guardPath 'guard-result.json')
}
