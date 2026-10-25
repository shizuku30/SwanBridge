[CmdletBinding()]
param([string]$LayoutDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'build\layout'))
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Add-Type -AssemblyName System.Drawing
function Check([bool]$Condition, [string]$Description) {
    if (!$Condition) { throw ('FAIL ' + $Description) }
    Write-Output ('PASS ' + $Description)
}
$ico = [System.IO.File]::ReadAllBytes((Join-Path $LayoutDirectory 'Assets\SwanBridge.ico'))
$nativeSizes = @(for ($i=0; $i -lt [BitConverter]::ToUInt16($ico,4); $i++) {
    if ($ico[6+16*$i]) { [int]$ico[6+16*$i] } else { 256 }
})
Check (@(16,24,32,48,128,256 | Where-Object { $nativeSizes -notcontains $_ }).Count -eq 0) 'ICO contains small and high-resolution frames generated from the supplied PNG'
[xml]$manifest = Get-Content -LiteralPath (Join-Path $LayoutDirectory 'AppxManifest.xml') -Raw
$visuals = @($manifest.Package.Applications.Application | ForEach-Object { $_.VisualElements })
Check (@($visuals | Where-Object BackgroundColor -ne 'transparent').Count -eq 0 -and $visuals.Count -eq 2) 'foreground and provider icons have transparent Windows backplates'
$expected = @{}
foreach ($entry in @(@('StoreLogo',50),@('Square44x44Logo',44),@('Square150x150Logo',150))) {
    $expected[$entry[0]+'.png'] = [int]$entry[1]
    foreach ($scale in @(125,150,200,400)) {
        $expected[$entry[0]+'.scale-'+$scale+'.png'] = [int][Math]::Round([int]$entry[1]*$scale/100.0,[MidpointRounding]::AwayFromZero)
    }
}
foreach ($size in @(16,20,24,30,32,36,40,48,60,64,72,80,96,256)) {
    foreach ($variant in @('','_altform-unplated','_altform-lightunplated')) {
        $expected['Square44x44Logo.targetsize-'+$size+$variant+'.png'] = $size
    }
}
$wrongSize = @(); $wrongAlpha = @()
foreach ($name in $expected.Keys) {
    $bitmap = [System.Drawing.Bitmap]::new((Join-Path $LayoutDirectory ('Assets\'+$name)))
    try {
        if ($bitmap.Width -ne $expected[$name] -or $bitmap.Height -ne $expected[$name]) { $wrongSize += $name }
        if ($bitmap.GetPixel(0,0).A -ne 0 -or $bitmap.GetPixel([int]($bitmap.Width/2),[int]($bitmap.Height/2)).A -lt 200) { $wrongAlpha += $name }
    } finally { $bitmap.Dispose() }
}
Check ($expected.Count -eq 57 -and !$wrongSize.Count) 'all 57 scale and theme icon assets have exact pixel dimensions'
Check (!$wrongAlpha.Count) 'all icon variants retain transparent corners and visible artwork'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class IconAssetProbe {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern IntPtr FindResource(IntPtr module, IntPtr name, IntPtr type);
    [DllImport("kernel32.dll")] static extern uint SizeofResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll")] static extern IntPtr LoadResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll")] static extern IntPtr LockResource(IntPtr resource);
    [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
    static byte[] Read(IntPtr module, int name, int type) {
        var resource=FindResource(module,new IntPtr(name),new IntPtr(type));
        if(resource==IntPtr.Zero) return new byte[0];
        var bytes=new byte[checked((int)SizeofResource(module,resource))];
        Marshal.Copy(LockResource(LoadResource(module,resource)),bytes,0,bytes.Length);
        return bytes;
    }
    public static bool MatchesIcon(string path, byte[] ico) {
        var module=LoadLibraryEx(path,IntPtr.Zero,0x22);
        if(module==IntPtr.Zero) return false;
        try {
            var group=Read(module,1,14);
            int count=BitConverter.ToUInt16(ico,4);
            if(group.Length!=6+14*count || BitConverter.ToUInt16(group,4)!=count) return false;
            for(int i=0;i<count;i++) {
                int entry=6+16*i, grouped=6+14*i;
                var frame=Read(module,BitConverter.ToUInt16(group,grouped+12),3);
                int size=checked((int)BitConverter.ToUInt32(ico,entry+8));
                int offset=checked((int)BitConverter.ToUInt32(ico,entry+12));
                if(frame.Length!=size || ico[entry]!=group[grouped] || ico[entry+1]!=group[grouped+1]) return false;
                for(int b=0;b<size;b++) if(frame[b]!=ico[offset+b]) return false;
            }
            return true;
        }
        finally { FreeLibrary(module); }
    }
}
'@
Check ([IconAssetProbe]::MatchesIcon((Join-Path $LayoutDirectory 'SwanBridge.App.exe'),$ico) -and
    [IconAssetProbe]::MatchesIcon((Join-Path $LayoutDirectory 'SwanBridge.Host.exe'),$ico)) 'both executables embed every new ICO frame byte-for-byte'
Check ((Get-Item -LiteralPath (Join-Path $LayoutDirectory 'resources.pri')).Length -gt 32) 'MSIX includes a resource index for scale and unplated icon selection'
