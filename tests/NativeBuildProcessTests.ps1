$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/NativeBuildProcess.ps1')
function Check([bool]$Condition, [string]$Description) {
    if (!$Condition) { throw ('FAIL ' + $Description) }
    Write-Output ('PASS ' + $Description)
}
$shell = Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
$output = @(Invoke-NativeBuildProcess -FilePath $shell -Arguments @('-NoProfile', '-Command', "[Console]::Error.WriteLine('expected warning'); exit 0"))
Check (($output -join "`n") -match 'expected warning') 'native stderr is retained as diagnostic text without failing a successful process'
Check ($ErrorActionPreference -eq 'Stop') 'native execution preserves the caller error preference'
$rejected = $false
try { Invoke-NativeBuildProcess -FilePath $shell -Arguments @('-NoProfile', '-Command', 'exit 7') } catch { $rejected = $_.Exception.Message -match 'exit code 7' }
Check $rejected 'a nonzero native exit still fails the build'
$global:LASTEXITCODE = 0
