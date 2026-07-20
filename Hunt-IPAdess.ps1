param(
    [string]$TargetIP = "172.217.22.174",
    [switch]$EnrichWithNmap
)

. "$PSScriptRoot\Nmap-Helper.ps1"
 $alreadyScanned = $false

Write-Host "Hunting for connections to $TargetIP... Press Ctrl+C to stop." -ForegroundColor Cyan
if ($EnrichWithNmap) { Write-Host "[*] Will run nmap service scan on first detection." -ForegroundColor Green }

while ($true) {
    $connections = Get-NetTCPConnection -RemoteAddress $TargetIP -ErrorAction SilentlyContinue
    if ($connections) {
        foreach ($conn in $connections) {
            $pidVal = $conn.OwningProcess
            if ($pidVal) {
                $proc = Get-Process -Id $pidVal -ErrorAction SilentlyContinue
                $path = $null
                if ($proc) { try { $path = $proc.Path } catch {} }

                Write-Host "`n[!!!] CONNECTION FOUND !!!" -ForegroundColor Red
                Write-Host "     Process ID  : $pidVal" -ForegroundColor Yellow
                Write-Host "     Process Name: $($proc.ProcessName)" -ForegroundColor Yellow
                Write-Host "     Executable  : $path" -ForegroundColor Yellow
                Write-Host "     Local Port  : $($conn.LocalPort)" -ForegroundColor Yellow
                Write-Host "     State       : $($conn.State)" -ForegroundColor Yellow

                if ($EnrichWithNmap -and -not $alreadyScanned) {
                    $alreadyScanned = $true
                    Write-Host "     [nmap] Service scan in progress..." -ForegroundColor Magenta
                    $r = Get-NmapServiceInfo -IP $TargetIP -TopPorts 100 -TimeoutSec 60
                    if ($r) {
                        Write-Host "     [nmap] Hostname: $($r.Hostname) | OS: $($r.OS)" -ForegroundColor Green
                        foreach ($p in $r.Ports | Where-Object { $_.State -eq 'open' }) {
                            Write-Host ("     [nmap] {0}/{1} {2} {3} {4}" -f $p.Port,$p.Proto,$p.Service,$p.Product,$p.Version) -ForegroundColor Green
                        }
                    }
                }
                Write-Host "-----------------------------------" -ForegroundColor Cyan
            }
        }
    }
    Start-Sleep -Milliseconds 500
}