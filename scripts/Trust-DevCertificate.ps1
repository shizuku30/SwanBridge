#Requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
[xml]$manifest = Get-Content -LiteralPath (Join-Path $root 'package\AppxManifest.xml') -Raw
$package = Join-Path $root ('dist\{0}_{1}_{2}.msix' -f $manifest.Package.Identity.Name,$manifest.Package.Identity.Version,$manifest.Package.Identity.ProcessorArchitecture)
$publicCertificate = Join-Path $root 'dist\SwanBridge.Development.cer'
$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($publicCertificate)
$signature = Get-AuthenticodeSignature -LiteralPath $package
if ($certificate.Subject -ne 'CN=SwanBridge Development' -or !$signature.SignerCertificate -or
    $signature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
    throw 'Certificate and package signer do not match. Nothing was trusted.'
}
if ($certificate.HasPrivateKey) { throw 'Only a public certificate should be imported.' }
Write-Output "Trusting the local development publisher: $($certificate.Subject)"
Write-Output "Thumbprint: $($certificate.Thumbprint)"
# TrustedPeople authorizes packages from this publisher, not only this one build.
# Never add the development certificate to Trusted Root Certification Authorities.
Import-Certificate -FilePath $publicCertificate -CertStoreLocation Cert:\LocalMachine\TrustedPeople |
    Select-Object Subject,Thumbprint,NotAfter
