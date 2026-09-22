<#
    Build-CloudBlockerTray.ps1
    Generates the tray icon and compiles CloudBlockerTray.cs into a standalone
    Windows executable using the .NET Framework compiler that ships with Windows.
    No external dependencies, no PowerShell module install required.
#>

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

$csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $csc)) { throw 'csc.exe not found (need .NET Framework 4.x).' }

$cs   = Join-Path $root 'CloudBlockerTray.cs'
$man  = Join-Path $root 'app.manifest'
$ico  = Join-Path $root 'cb.ico'
$out  = Join-Path $root 'CloudBlockerTray.exe'

# ---- 1. Generate the icon (blue shield-ish tile with "CB") ----
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap 32, 32
$g   = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::Transparent)
$bg    = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 28, 84, 168))
$red   = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 214, 57, 57))
$font  = New-Object System.Drawing.Font ('Segoe UI', 12, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
$sf    = New-Object System.Drawing.StringFormat
$sf.Alignment = [System.Drawing.StringAlignment]::Center
$sf.LineAlignment = [System.Drawing.StringAlignment]::Center
$g.FillRectangle($bg, 2, 2, 28, 28)
$g.FillRectangle($red, 5, 24, 22, 4)
$g.DrawString('CB', $font, [System.Drawing.Brushes]::White, (New-Object System.Drawing.RectangleF 0, 0, 32, 27), $sf)
$g.Dispose()
$hIcon = $bmp.GetHicon()
$icon  = [System.Drawing.Icon]::FromHandle($hIcon)
$fs = [System.IO.File]::Create($ico)
$icon.Save($fs)
$fs.Close()
$bmp.Dispose()
Write-Host "Icon written: $ico"

# ---- 2. Compile ----
& $csc /nologo /target:winexe /platform:anycpu /optimize+ `
    "/out:$out" "/win32icon:$ico" "/win32manifest:$man" `
    /r:System.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll `
    $cs
if ($LASTEXITCODE -ne 0) { throw "csc failed with exit code $LASTEXITCODE" }
Write-Host "Compiled: $out"
Get-Item $out | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
