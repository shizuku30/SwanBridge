[CmdletBinding()]
param([string]$LayoutDirectory, [string]$MakePriPath)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
function Check([bool]$Condition, [string]$Description) {
    if (!$Condition) { throw ('FAIL ' + $Description) }
    Write-Output ('PASS ' + $Description)
}
function Catalog([string]$Path) {
    [xml]$xml = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $result = @{}
    foreach ($entry in $xml.root.data) {
        if ($result.ContainsKey($entry.name)) { throw 'Duplicate localization resource key' }
        $value = $entry.SelectSingleNode('value').InnerText
        if ([string]::IsNullOrWhiteSpace($value)) { throw 'Empty localization resource value' }
        $result.Add($entry.name, $value)
    }
    return $result
}
$en = Catalog (Join-Path $root 'package/Strings/en-US/Resources.resw')
$zh = Catalog (Join-Path $root 'package/Strings/zh-Hans/Resources.resw')
Check ($en.Count -ge 170 -and $en.Count -eq $zh.Count -and !@(Compare-Object @($en.Keys | Sort-Object) @($zh.Keys | Sort-Object)).Count) 'English and Simplified Chinese catalogs have identical complete key sets'
Check (!@($en.Values | Where-Object { $_ -match '[\u3400-\u4DBF\u4E00-\u9FFF]' }).Count) 'English resources contain no untranslated Chinese'
foreach ($key in $en.Keys) {
    $englishTokens = @([regex]::Matches($en[$key], '\{\d+\}') | ForEach-Object Value | Sort-Object)
    $chineseTokens = @([regex]::Matches($zh[$key], '\{\d+\}') | ForEach-Object Value | Sort-Object)
    if (($englishTokens -join ',') -ne ($chineseTokens -join ',')) { throw ('Mismatched format arguments: ' + $key) }
}
Check $true 'localized format arguments match between catalogs'
$app = Get-Content -LiteralPath (Join-Path $root 'src/App.cpp') -Raw -Encoding UTF8
$resources = Get-Content -LiteralPath (Join-Path $root 'src/UiResources.h') -Raw
$plugin = Get-Content -LiteralPath (Join-Path $root 'src/Plugin.cpp') -Raw
$used = @([regex]::Matches($app + $resources, 'L"((?:UI_|Provider)[A-Za-z][A-Za-z0-9_]*)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
Check (!@($used | Where-Object { !$en.ContainsKey($_) }).Count) 'all application and provider resource references resolve'
Check ($app -notmatch '[\u3400-\u4DBF\u4E00-\u9FFF]') 'UI text is extracted from C++ into resource files'
Check ($resources -match 'GlobalizationPreferences::Languages\(\)' -and $resources -match 'preferred.GetAt\(0\)' -and
    $resources -match 'context.Languages\(' -and ($app + $resources) -notmatch 'PrimaryLanguageOverride|SetGlobalQualifierValue') 'system primary language selects an explicit non-persistent resource context'
Check ($app -match 'languageQualifiers.MapChanged\(auto_revoke' -and $app -match 'self->RefreshSystemLanguage\(\)' -and
    $app -match 'viewRoot.Language\(strings.language\)') 'system language events and activation update the existing interface'
Check ($app -match 'ResourceContext languageContext\{ nullptr \}' -and $app -match 'IObservableMap<hstring, hstring> languageQualifiers\{ nullptr \}' -and
    $app.IndexOf('languageContext{ nullptr }') -lt $app.IndexOf('MapChanged_revoker languageChanged') -and
    $app.IndexOf('languageQualifiers{ nullptr }') -lt $app.IndexOf('MapChanged_revoker languageChanged') -and
    $app -match 'languageQualifiers = languageContext.QualifierValues\(\)' -and
    $app -notmatch 'GetForCurrentView\(\)\s*\.QualifierValues\(\).MapChanged') 'language context and event source stay alive until the weak revoker has unsubscribed'
$refresh = [regex]::Match($app, '(?s)void RefreshSystemLanguage\(\).*?(?=void RefreshChoiceLabels)')
Check ($refresh.Success -and $refresh.Value -match 'for \(auto const& update : localized\)' -and
    $refresh.Value -notmatch 'Load\(|ApplyOptions\(|Password\(|CaptureEditor\(') 'language changes do not rebuild the editor or discard unsaved fields and credentials'
Check ($app -match 'item.Tag\(box_value\(entry.second\)\)' -and $app -match 'target.Content\(box_value\(value\)\)') 'translated combo labels retain invariant configuration values'
$choices = [regex]::Match($app, '(?s)void RefreshChoiceLabels\(\).*?(?=void WatchSystemLanguage)')
Check ($choices.Success -and $refresh.Value -match 'RefreshChoiceLabels\(\)' -and
    $choices.Value -match 'selected = combo.SelectedIndex\(\)' -and
    $choices.Value -match 'combo.SelectedIndex\(-1\); combo.SelectedIndex\(selected\)' -and
    $choices.Value -notmatch '\.Tag\(|Items\(\).Clear|ApplyOptions\(') 'collapsed combo labels are refreshed by restoring the exact selection without rewriting option values'
Check ($app -match 'BindTip\(info, key\)' -and $app -match 'LocalText\(key, 13\)' -and
    $app -match 'UI_HelpSuffix' -and $app -match 'UI_UnsavedTitle') 'tooltips, flyouts, accessibility names and dialogs are localized'
$fixedBinding = [regex]::Match($app, '(?s)void Bind\(.*?(?=template<typename Target, typename Setter>\s*void BindTransient)')
Check ($fixedBinding.Success -and $fixedBinding.Value -match '\[this, target, key, setter\]' -and
    $fixedBinding.Value -notmatch 'make_weak') 'fixed UI bindings retain projected controls so tree-only labels can refresh'
Check ($app -match 'void BindTransient\(' -and ([regex]::Matches($app, 'BindTransient\(dialog,')).Count -eq 4) 'temporary dialogs do not become permanently retained by localization callbacks'
Check ($plugin -match 'TerminateConnection\(LocalizedProviderError' -and $plugin -match 'SetErrorMessage\(LocalizedProviderError' -and
    $plugin -match 'FailureDetail", box_value\(error.message\(\)\)') 'Windows VPN error text is localized while diagnostic codes and details remain stable'
[xml]$manifest = Get-Content -LiteralPath (Join-Path $root 'package/AppxManifest.xml') -Raw
$languages = @($manifest.Package.Resources.Resource.Language | Sort-Object)
Check (($languages -join ',') -eq 'en-US,zh-Hans') 'the package declares exactly English and Simplified Chinese'
if ($LayoutDirectory) {
    Check ((Test-Path (Join-Path $LayoutDirectory 'Strings/en-US/Resources.resw')) -and
        (Test-Path (Join-Path $LayoutDirectory 'Strings/zh-Hans/Resources.resw'))) 'both catalogs are copied into the package layout'
    Check ((Get-Item -LiteralPath (Join-Path $LayoutDirectory 'resources.pri')).Length -gt 32) 'localized package includes its compiled resource index'
    if ($MakePriPath) {
        $dump = Join-Path (Split-Path -Parent $LayoutDirectory) 'localization-resources.xml'
        & $MakePriPath dump /if (Join-Path $LayoutDirectory 'resources.pri') /of $dump /dt detailed /o | Out-Null
        if ($LASTEXITCODE) { throw 'Could not inspect the compiled resource index' }
        [xml]$index = Get-Content -LiteralPath $dump -Raw -Encoding UTF8
        $compiled = @($index.SelectNodes('//ResourceMapSubtree[@name="Resources"]/NamedResource'))
        Check ($compiled.Count -eq $en.Count) 'all localization keys are present in resources.pri'
        foreach ($entry in $compiled) {
            $englishCandidate = $entry.SelectSingleNode('Candidate[QualifierSet/Qualifier[@name="Language" and @value="en-US"]]/Value')
            $chineseCandidate = $entry.SelectSingleNode('Candidate[QualifierSet/Qualifier[@name="Language" and @value="zh-Hans"]]/Value')
            if (!$englishCandidate -or !$chineseCandidate -or $englishCandidate.InnerText -ne $en[$entry.name] -or
                $chineseCandidate.InnerText -ne $zh[$entry.name]) { throw ('Compiled translation or language qualifier mismatch: ' + $entry.name) }
        }
        Check $true 'the compiled index preserves both translations for every key'
        $englishDefault = $compiled[0].SelectSingleNode('Decision/QualifierSet/Qualifier[@name="Language" and @value="en-US"]')
        Check ($englishDefault.scoreAsDefault -eq '1.0') 'the compiled package default language is English'
    }
}
