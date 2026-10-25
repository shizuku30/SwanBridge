#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$app = Get-Content -LiteralPath (Join-Path $root 'src\App.cpp') -Raw
function Check([bool]$Condition, [string]$Description) {
    if (!$Condition) { throw ('FAIL ' + $Description) }
    Write-Output ('PASS ' + $Description)
}
Check ($app -match 'double edge = 36' -and $app -match 'SizedButton\(144, 36\)' -and
    $app -match 'SizedButton\(edge, edge\)') 'toolbar and paired command buttons use stable shared dimensions'
Check ($app -match 'FontIcon icon; icon.FontSize\(16\)' -and $app -notmatch 'SymbolIcon icon' -and
    $app -match 'icon.IsTextScaleFactorEnabled\(false\)' -and $app -notmatch 'icon.Width\(') 'font glyphs retain natural measurements inside their centered slots'
Check ($app -match 'SetCommandLabel\(create,' -and $app -notmatch 'create.Content\(' -and
    $app -match 'Children\(\).GetAt\(1\).as<TextBlock>\(\).Text\(value\)') 'profile selection preserves the save icon and command layout'
Check ($app -notmatch 'SolidColorBrush|Application::Current\(\).RequestedTheme\(' -and
    $app -match 'ThemeResource ApplicationPageBackgroundThemeBrush' -and
    $app -match 'ThemeResource SystemControlForegroundBaseHighBrush' -and
    $app -match 'ThemeResource SystemControlBackgroundChromeMediumLowBrush') 'backgrounds and inherited foreground use dynamic theme resources rather than fixed colors'
Check ($app -match 'appearance.ColorValuesChanged\(auto_revoke' -and $app -match 'dispatcher.RunAsync' -and
    $app -match 'themeActivated = Window::Current\(\).Activated\(auto_revoke') 'system color changes and activation refresh the existing UI on its dispatcher'
Check ($app -match 'FollowOwnerTheme\(tip,' -and $app -match 'FlyoutPresenterStyle\(style\)' -and
    $app -match 'GetOpenPopupsForXamlRoot' -and $app -match 'dialog.RequestedTheme\(viewRoot.ActualTheme\(\)\)') 'tooltips, flyouts, open popups and confirmation dialogs synchronize their themes'
