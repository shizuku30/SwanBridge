[CmdletBinding()]
param([switch]$SkipTests, [switch]$ToolsOnly, [switch]$AcceptanceHooks, [string]$TestRuntimeDirectory)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vs) { throw 'Visual Studio C++ tools were not found.' }
$vc = Get-ChildItem -LiteralPath (Join-Path $vs 'VC\Tools\MSVC') -Directory | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$sdk = Get-ChildItem -LiteralPath (Join-Path $kits 'Include') -Directory |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'cppwinrt\winrt\Windows.Networking.Vpn.h') } |
    Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (!$sdk) { throw 'A Windows SDK with C++/WinRT headers is required.' }
$cl = Join-Path $vc.FullName 'bin\Hostx64\x64\cl.exe'
$build = Join-Path $root 'build'
$layout = Join-Path $build 'layout'
$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force -Path $build,$layout,$dist,(Join-Path $layout 'Assets') | Out-Null
$include = @("/I$($vc.FullName)\include", "/I$root\src")
foreach ($part in @('ucrt','shared','um','winrt','cppwinrt')) { $include += "/I$($sdk.FullName)\$part" }
$lib = @("/LIBPATH:$($vc.FullName)\lib\x64\store", "/LIBPATH:$($vc.FullName)\lib\x64",
    "/LIBPATH:$kits\Lib\$($sdk.Name)\ucrt\x64", "/LIBPATH:$kits\Lib\$($sdk.Name)\um\x64")
$desktopLib = @("/LIBPATH:$($vc.FullName)\lib\x64", "/LIBPATH:$kits\Lib\$($sdk.Name)\ucrt\x64", "/LIBPATH:$kits\Lib\$($sdk.Name)\um\x64")
$flags = @('/nologo','/std:c++20','/EHsc','/W4','/O2','/MD','/utf-8','/permissive-',
    '/DUNICODE','/D_UNICODE','/D_WIN32_WINNT=0x0A00') + $include
$appFlags = @('/DWINAPI_FAMILY=WINAPI_FAMILY_APP','/DWINRT_LEAN_AND_MEAN')
if ($AcceptanceHooks) { $appFlags += '/DSWANBRIDGE_ACCEPTANCE_HOOKS' }

function Invoke-Compiler([string[]]$Arguments) {
    & $cl @Arguments
    if ($LASTEXITCODE -ne 0) { throw "C++ build failed with exit code $LASTEXITCODE" }
}
Push-Location $build
try {
    Invoke-Compiler ($flags + @("$root\tests\ActivateApp.cpp", '/FoActivateApp.obj', '/FeActivateApp.exe', '/link') + $desktopLib + @('windowsapp.lib','ole32.lib','uuid.lib'))
    if (!$ToolsOnly) {
    & (Join-Path $PSScriptRoot 'Generate-IconAssets.ps1') -OutputDirectory (Join-Path $layout 'Assets')
    $rc = Join-Path $kits "bin\$($sdk.Name)\x64\rc.exe"
    & $rc /nologo "/I$layout\Assets" "/fo$build\App.res" "$root\src\App.rc"
    if ($LASTEXITCODE -ne 0) { throw 'Application icon resource compilation failed.' }
    Invoke-Compiler ($flags + $appFlags + @('/LD', "$root\src\Plugin.cpp", '/FoPlugin.obj', "/Fe$layout\SwanBridge.Plugin.dll",
        '/link', "/DEF:$root\src\Plugin.def", "/IMPLIB:$build\SwanBridge.Plugin.lib", '/APPCONTAINER','/DYNAMICBASE','/NXCOMPAT') + $lib + @('windowsapp.lib'))
    Invoke-Compiler ($flags + $appFlags + @("$root\src\Host.cpp", 'App.res', '/FoHost.obj', "/Fe$layout\SwanBridge.Host.exe",
        '/link','/SUBSYSTEM:WINDOWS','/APPCONTAINER','/DYNAMICBASE','/NXCOMPAT') + $lib + @('windowsapp.lib'))
    Invoke-Compiler ($flags + $appFlags + @("$root\src\App.cpp", 'App.res', '/FoApp.obj', "/Fe$layout\SwanBridge.App.exe",
        '/link','/SUBSYSTEM:WINDOWS','/APPCONTAINER','/DYNAMICBASE','/NXCOMPAT') + $lib + @('windowsapp.lib'))
    }
    if (!$SkipTests) {
        Invoke-Compiler ($flags + @("$root\tests\ContractTests.cpp", '/FoContractTests.obj', '/FeContractTests.exe', '/link') + $desktopLib + @('kernel32.lib','windowsapp.lib'))
        & (Join-Path $build 'ContractTests.exe')
        if ($LASTEXITCODE -ne 0) { throw 'Contract tests failed.' }
        Invoke-Compiler ($flags + @("$root\tests\LanguageObserverTests.cpp", '/FoLanguageObserverTests.obj', '/FeLanguageObserverTests.exe', '/link') + $desktopLib + @('windowsapp.lib'))
        & (Join-Path $build 'LanguageObserverTests.exe')
        if ($LASTEXITCODE -ne 0) { throw 'Language event-owner lifetime tests failed.' }
        Invoke-Compiler ($flags + @("$root\tests\ProfileConfigurationTests.cpp", '/FoProfileConfigurationTests.obj', '/FeProfileConfigurationTests.exe', '/link') + $desktopLib + @('windowsapp.lib'))
        & (Join-Path $build 'ProfileConfigurationTests.exe')
        if ($LASTEXITCODE -ne 0) { throw 'Profile configuration tests failed.' }
        Invoke-Compiler ($flags + @("$root\tests\CredentialProbe.cpp", '/FoCredentialProbe.obj', '/FeCredentialProbe.exe', '/link') + $desktopLib + @('windowsapp.lib'))
        & (Join-Path $build 'CredentialProbe.exe')
        if ($LASTEXITCODE -ne 0) { throw 'Credential protection tests failed.' }
        Invoke-Compiler ($flags + @("$root\tests\ActivationProbe.cpp", '/FoActivationProbe.obj', '/FeActivationProbe.exe', '/link') + $desktopLib + @('windowsapp.lib'))
        if ($TestRuntimeDirectory) {
            if ([IO.Path]::IsPathRooted($TestRuntimeDirectory)) { throw 'Use a workspace-relative test-runtime directory.' }
            $runtimePath = (Resolve-Path -LiteralPath (Join-Path $root $TestRuntimeDirectory)).Path
            if (!$runtimePath.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
                !(Test-Path (Join-Path $runtimePath 'msvcp140_app.dll'))) { throw 'Invalid workspace-local test runtime.' }
        } else {
            $runtime = Get-AppxPackage -Name Microsoft.VCLibs.140.00 | Where-Object Architecture -eq 'X64' | Select-Object -First 1
            if (!$runtime) { throw 'The x64 Microsoft.VCLibs.140.00 runtime is required, or pass -TestRuntimeDirectory.' }
            $runtimePath = $runtime.InstallLocation
        }
        $oldPath = $env:PATH
        try {
            $env:PATH = "$runtimePath;$oldPath"
            & (Join-Path $build 'ActivationProbe.exe') (Join-Path $layout 'SwanBridge.Plugin.dll')
            if ($LASTEXITCODE -ne 0) { throw 'Activation tests failed.' }
        } finally { $env:PATH = $oldPath }
        Invoke-Compiler ($flags + @("$root\tests\EngineAbiProbe.cpp", '/FoEngineAbiProbe.obj', '/FeEngineAbiProbe.exe', '/link') + $desktopLib + @('windowsapp.lib'))
        & (Join-Path $build 'EngineAbiProbe.exe') (Join-Path $build 'engine\SwanBridge.Engine.dll')
        if ($LASTEXITCODE -ne 0) { throw 'Native C ABI tests failed.' }
    }
} finally { Pop-Location }
if ($ToolsOnly) { return }

$engine = Join-Path $build 'engine'
if (!(Test-Path -LiteralPath (Join-Path $engine 'SwanBridge.Engine.dll'))) {
    throw 'Build the native engine with scripts\Build-Core.ps1 first.'
}
Get-ChildItem -LiteralPath $engine -File -Filter '*.dll' | Copy-Item -Destination $layout -Force
Copy-Item -LiteralPath (Join-Path $engine 'engine.conf'),(Join-Path $engine 'COPYING.strongswan') -Destination $layout -Force
Copy-Item -LiteralPath (Join-Path $engine 'licenses') -Destination $layout -Recurse -Force
Copy-Item -LiteralPath (Join-Path $root 'LICENSE'),(Join-Path $root 'LICENSING.md'),(Join-Path $root 'THIRD_PARTY_NOTICES.md') -Destination $layout -Force
Copy-Item -LiteralPath (Join-Path $root 'LICENSES/GPL-3.0.txt') -Destination (Join-Path $layout 'licenses/GPL-3.0.txt') -Force

Copy-Item -LiteralPath (Join-Path $root 'package\AppxManifest.xml') -Destination (Join-Path $layout 'AppxManifest.xml')
Copy-Item -LiteralPath (Join-Path $root 'package/Strings') -Destination $layout -Recurse -Force
foreach ($artifact in @('SwanBridge.Plugin.lib','SwanBridge.Plugin.exp')) {
    $path = Join-Path $layout $artifact
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
}
$makepri = Join-Path $kits "bin\$($sdk.Name)\x64\makepri.exe"
$priConfig = Join-Path $build 'priconfig.xml'
& $makepri createconfig /cf $priConfig /dq lang-en-US_scale-100 /pv 10.0.0 /o | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Icon resource-index configuration failed.' }
[xml]$resourceConfig = Get-Content -LiteralPath $priConfig -Raw
$null = $resourceConfig.resources.RemoveChild($resourceConfig.resources.packaging)
$resourceConfig.resources.index.SetAttribute('startIndexAt','')
$resourceConfig.Save($priConfig)
& $makepri new /pr $layout /cf $priConfig /mn (Join-Path $layout 'AppxManifest.xml') /of (Join-Path $layout 'resources.pri') /o | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Icon resource indexing failed.' }
if (!$SkipTests) {
    & (Join-Path $root 'tests\IconAssetTests.ps1') -LayoutDirectory $layout
    & (Join-Path $root 'tests\UiStyleTests.ps1')
    & (Join-Path $root 'tests\LocalizationTests.ps1') -LayoutDirectory $layout -MakePriPath $makepri
    foreach ($test in @('LocalVpnScriptTests.ps1','LifecycleScriptTests.ps1','MobikeScriptTests.ps1','MobikeRouteTests.ps1','RekeyScriptTests.ps1','OpenClashPolicyTests.ps1')) {
        & (Join-Path $root ('tests\' + $test))
    }
}
$makeappx = Join-Path $kits "bin\$($sdk.Name)\x64\makeappx.exe"
[xml]$manifest = Get-Content -LiteralPath (Join-Path $layout 'AppxManifest.xml') -Raw
$packageName = '{0}_{1}_{2}.msix' -f $manifest.Package.Identity.Name,$manifest.Package.Identity.Version,$manifest.Package.Identity.ProcessorArchitecture
& $makeappx pack /d $layout /p (Join-Path $dist $packageName) /o | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'MSIX packaging failed.' }
Write-Output "Build complete: $(Join-Path $dist $packageName)"
Write-Output "Development layout: $layout"
