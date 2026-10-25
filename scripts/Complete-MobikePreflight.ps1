#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PreflightDirectory,
    [Parameter(Mandatory=$true)][string]$ServerCaptureDirectory
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'MobikeEvidence.ps1')
. (Join-Path $PSScriptRoot 'MobikeServerEvidence.ps1')
$directory=(Resolve-Path -LiteralPath $PreflightDirectory).Path
$preflight=Get-Content -LiteralPath (Join-Path $directory 'result.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$probe=Get-Content -LiteralPath (Join-Path $directory 'probe\result.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if (!$preflight.NetworkRestored -or !$preflight.EngineStopped -or !$probe.ClientEvidencePassed -or $probe.Mode -ne 'Probe') {
    throw 'A completed client transport preflight with verified cleanup is required.'
}
if ([version]$probe.PackageVersion -lt [version]'0.1.0.36') { throw 'Use normalized host-order IKE SPI diagnostics from package 0.1.0.36 or newer.' }
$spi=[uint64]::Parse([string]$probe.Before.IkeSpiInitiator).ToString('x16')
$records=@(Get-ChildItem -LiteralPath $ServerCaptureDirectory -File -Filter 'sample-*.json' |
    Sort-Object { [int]($_.BaseName -replace '\D','') } | ForEach-Object {
        $report=Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($entry in $report.data) {
            if (@($entry.PSObject.Properties | Where-Object { $_.Value.'initiator-spi' -ceq $spi -and $_.Value.state -eq 'ESTABLISHED' }).Count) {
                [pscustomobject]@{ File=$_.Name; Report=$report }
                break
            }
        }
    })
if ($records.Count -lt 2) { throw 'Insufficient server snapshots for this exact client IKE SPI.' }
$evidence=Test-MobikeServerEvidence $probe.Before $probe.After $records[0].Report $records[-1].Report -ProbeOnly
$result=[ordered]@{ Accepted=$evidence.Passed; Outcome=$evidence.Outcome; PhysicalNetworkMigrationAccepted=$false;
    NetworkRestored=$preflight.NetworkRestored; EngineStopped=$preflight.EngineStopped;
    ClientBefore=$probe.Before; ClientAfter=$probe.After; ServerEvidence=$evidence;
    ServerBeforeFile=$records[0].File; ServerAfterFile=$records[-1].File; CompletedAt=[DateTimeOffset]::Now.ToString('o') }
[IO.File]::WriteAllText((Join-Path $directory 'verified-result.json'),($result|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
$result | Select-Object Accepted,Outcome,PhysicalNetworkMigrationAccepted,NetworkRestored,EngineStopped,ServerBeforeFile,ServerAfterFile | ConvertTo-Json
if (!$result.Accepted) { throw ($evidence.Failures -join '; ') }
