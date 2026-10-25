function Invoke-NativeBuildProcess {
    param([string]$FilePath, [string[]]$Arguments)
    $previous = $ErrorActionPreference
    try {
        # Windows PowerShell wraps redirected stderr as ErrorRecord even on a successful native exit.
        $ErrorActionPreference = 'Continue'
        & $FilePath @Arguments 2>&1 | ForEach-Object { [string]$_ }
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
    if ($code -ne 0) { throw ('Native build process {0} failed with exit code {1}.' -f [IO.Path]::GetFileName($FilePath), $code) }
}
