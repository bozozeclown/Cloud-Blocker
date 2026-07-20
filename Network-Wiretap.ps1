param(
    [switch]$AutoEnrich,
    [int]   $MinScanIntervalMin = 60
)

. "$PSScriptRoot\Nmap-Helper.ps1"

 $logFile        = "$PSScriptRoot\NetworkWiretap.csv"
 $enrichFile     = "$PSScriptRoot\NetworkWiretap-Enriched.csv"
 $scanStateFile  = "$PSScriptRoot\NetworkWiretap-ScanState.xml"

 $scanHistory = @{}
if (Test-Path $scanStateFile) { $scanHistory = Import-Clixml $scanStateFile }

if (Test-Path $logFile)    { Remove-Item $logFile    -Force }
if ($AutoEnrich -and (Test-Path $enrichFile)) { Remove-Item $enrichFile -Force }

Write-Host "Starting Network Wiretap..." -ForegroundColor Cyan
if ($AutoEnrich) {
    Write-Host "[*] Auto-Enrichment ENABLED (Cooldown: ${MinScanIntervalMin}m)" -ForegroundColor Green
}
Write-Host "Logging to: $logFile" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop." -ForegroundColor Cyan

 $localIPs = (Get-NetIPAddress -AddressFamily IPv4).IPAddress

while ($true) {
    $connections = Get-NetTCPConnection -State Established, SynSent -ErrorAction SilentlyContinue
    foreach ($conn in $connections) {
        $remoteIP = $conn.RemoteAddress
        if ($remoteIP -notin $localIPs -and $remoteIP -notmatch '^(127\.|192\.168\.|10\.|172\.)') {
            $procId = $conn.OwningProcess
            $procName = "Unknown"; $procPath = "Unknown"
            if ($procId -ne 0) {
                $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
                if ($proc) {
                    $procName = $proc.ProcessName
                    try { $procPath = $proc.Path } catch {}
                }
            } else { $procName = "System Kernel" }

            $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            $logEntry = [PSCustomObject]@{
                Time=$timestamp; Process=$procName; PID=$procId; Path=$procPath
                RemoteIP=$remoteIP; RemotePort=$conn.RemotePort
            }
            $logEntry | Export-Csv -Path $logFile -Append -NoTypeInformation -Force
            Write-Host "[$timestamp] $procName ($procId) -> $remoteIP : $($conn.RemotePort)" -ForegroundColor Yellow

            if ($AutoEnrich) {
                $shouldScan = $true
                if ($scanHistory.ContainsKey($remoteIP)) {
                    if (((Get-Date) - $scanHistory[$remoteIP]).TotalMinutes -lt $MinScanIntervalMin) {
                        $shouldScan = $false
                    }
                }
                if ($shouldScan) {
                    Write-Host "    [scan] Enriching $remoteIP ..." -ForegroundColor Magenta
                    try {
                        $results = Get-ScanResult -IP $remoteIP -TimeoutSec 45
                        if ($results) {
                            foreach ($p in $results.Ports | Where-Object { $_.State -eq 'open' }) {
                                $enrich = [PSCustomObject]@{
                                    Time=$timestamp; RemoteIP=$remoteIP
                                    Hostname=$results.Hostname; OS=$results.OS
                                    Port=$p.Port; Service=$p.Service
                                    Product=$p.Product; Version=$p.Version
                                }
                                $enrich | Export-Csv -Path $enrichFile -Append -NoTypeInformation -Force
                                Write-Host "    [scan] $($results.Host) $($p.Port)/$($p.Proto) $($p.Service) $($p.Product) $($p.Version)" -ForegroundColor Green
                            }
                        }
                    } catch { Write-Host "    [scan] Scan failed: $_" -ForegroundColor Red }
                    $scanHistory[$remoteIP] = Get-Date
                    $scanHistory | Export-Clixml $scanStateFile
                }
            }
        }
    }
    Start-Sleep -Milliseconds 500
}