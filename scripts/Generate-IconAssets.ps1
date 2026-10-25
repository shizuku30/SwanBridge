[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'package\Assets\SwanBridge.png'
if (!(Test-Path -LiteralPath $source)) { throw 'The repository-local application PNG is missing.' }
Add-Type -AssemblyName System.Drawing
$image = [System.Drawing.Bitmap]::new($source)
$null = New-Item -ItemType Directory -Force -Path $OutputDirectory

function New-IconBitmap([int]$Size) {
    $bitmap = [System.Drawing.Bitmap]::new($Size,$Size,[System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $attributes = [System.Drawing.Imaging.ImageAttributes]::new()
    try {
        $graphics.Clear([System.Drawing.Color]::Transparent)
        $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
        $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $attributes.SetWrapMode([System.Drawing.Drawing2D.WrapMode]::TileFlipXY)
        $graphics.DrawImage($image,[System.Drawing.Rectangle]::new(0,0,$Size,$Size),
            0,0,$image.Width,$image.Height,[System.Drawing.GraphicsUnit]::Pixel,$attributes)
        return $bitmap
    } catch { $bitmap.Dispose(); throw }
    finally { $attributes.Dispose(); $graphics.Dispose() }
}

function Write-IconPng([string]$Name, [int]$Size) {
    $bitmap = New-IconBitmap $Size
    try { $bitmap.Save((Join-Path $OutputDirectory $Name),[System.Drawing.Imaging.ImageFormat]::Png) }
    finally { $bitmap.Dispose() }
}

try {
    if ($image.Width -ne $image.Height) { throw 'The application PNG must be square.' }
    foreach ($entry in @(@('StoreLogo',50),@('Square44x44Logo',44),@('Square150x150Logo',150))) {
        Write-IconPng ($entry[0]+'.png') ([int]$entry[1])
        foreach ($scale in @(125,150,200,400)) {
            $size = [int][Math]::Round([int]$entry[1]*$scale/100.0,[MidpointRounding]::AwayFromZero)
            Write-IconPng ($entry[0]+'.scale-'+$scale+'.png') $size
        }
    }
    foreach ($size in @(16,20,24,30,32,36,40,48,60,64,72,80,96,256)) {
        foreach ($variant in @('','_altform-unplated','_altform-lightunplated')) {
            Write-IconPng ('Square44x44Logo.targetsize-'+$size+$variant+'.png') $size
        }
    }

    # PNG-compressed ICO frames retain the original alpha channel on Windows 10/11.
    $frames = @(foreach ($size in @(16,20,24,32,40,48,64,128,256)) {
        $bitmap = New-IconBitmap $size
        $stream = [System.IO.MemoryStream]::new()
        try {
            $bitmap.Save($stream,[System.Drawing.Imaging.ImageFormat]::Png)
            [pscustomobject]@{ Size = $size; Bytes = $stream.ToArray() }
        } finally { $stream.Dispose(); $bitmap.Dispose() }
    })
    $file = [System.IO.File]::Create((Join-Path $OutputDirectory 'SwanBridge.ico'))
    $writer = [System.IO.BinaryWriter]::new($file)
    try {
        $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$frames.Count)
        $offset = 6 + 16 * $frames.Count
        foreach ($frame in $frames) {
            $dimension = [byte]$(if ($frame.Size -eq 256) { 0 } else { $frame.Size })
            $writer.Write($dimension); $writer.Write($dimension)
            $writer.Write([byte]0); $writer.Write([byte]0)
            $writer.Write([uint16]1); $writer.Write([uint16]32)
            $writer.Write([uint32]$frame.Bytes.Length); $writer.Write([uint32]$offset)
            $offset += $frame.Bytes.Length
        }
        foreach ($frame in $frames) { $writer.Write([byte[]]$frame.Bytes) }
    } finally { $writer.Dispose() }
} finally { $image.Dispose() }
Write-Output 'Generated transparent MSIX and multi-size EXE icons from package-relative SwanBridge.png.'
