[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
[xml]$manifest = Get-Content -LiteralPath (Join-Path $root 'package\AppxManifest.xml') -Raw
$package = Join-Path $root ('dist\{0}_{1}_{2}.msix' -f $manifest.Package.Identity.Name,$manifest.Package.Identity.Version,$manifest.Package.Identity.ProcessorArchitecture)
if (!(Test-Path -LiteralPath $package)) { throw 'Build the package first.' }
$subject = 'CN=SwanBridge Development'
$certificate = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
    $_.Subject -eq $subject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(7) -and
    $_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.3'
} | Sort-Object NotAfter -Descending | Select-Object -First 1
if (!$certificate) {
    $certificate = New-SelfSignedCertificate -Type Custom -Subject $subject -FriendlyName 'SwanBridge local development signing' `
        -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
        -KeyUsage DigitalSignature -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddYears(1) `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3','2.5.29.19={text}')
}
$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$signtool = Get-ChildItem -Path "$kits\*\x64\signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1
& $signtool.FullName sign /fd SHA256 /s My /sha1 $certificate.Thumbprint $package
if ($LASTEXITCODE -ne 0) { throw 'Package signing failed.' }
$publicCertificate = Join-Path $root 'dist\SwanBridge.Development.cer'
Export-Certificate -Cert $certificate -FilePath $publicCertificate -Force | Out-Null
$signature = Get-AuthenticodeSignature -LiteralPath $package
if (!$signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
    throw 'The signed package does not match the selected development certificate.'
}
Write-Output 'Package signed. The private key remains non-exportable in CurrentUser\My.'
Write-Output 'No machine trust store or development policy was changed.'
$certificate | Select-Object Subject,Thumbprint,NotAfter
Get-FileHash -LiteralPath $package -Algorithm SHA256 | Select-Object Hash,Path
