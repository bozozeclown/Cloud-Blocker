# Run as Administrator
 $logFile = "$PSScriptRoot\NetworkWiretap.csv"

# Remove old log if it exists
if (Test-Path $logFile) { Remove-Item $logFile -Force }

Write-Host "Starting Network Wiretap... Logging to: $logFile" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop." -ForegroundColor Cyan

# Cache local IPs so we don't log LAN traffic
 $localIPs = (Get-NetIPAddress -AddressFamily IPv4).IPAddress

while ($true) {
    # Get all active TCP connections
    $connections = Get-NetTCPConnection -State Established, SynSent -ErrorAction SilentlyContinue
    
    foreach ($conn in $connections) {
        $remoteIP = $conn.RemoteAddress
        
        # Ignore local network traffic (router, localhost)
        if ($remoteIP -notin $localIPs -and $remoteIP -notmatch '^(127\.|192\.168\.|10\.|172\.)') {
            $procId = $conn.OwningProcess
            $procName = "Unknown"
            $procPath = "Unknown"
            
            if ($procId -ne 0) {
                $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
                if ($proc) {
                    $procName = $proc.ProcessName
                    try { $procPath = $proc.Path } catch {}
                }
            } else {
                $procName = "System Kernel"
            }
            
            $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            $logEntry = [PSCustomObject]@{
                Time       = $timestamp
                Process    = $procName
                PID        = $procId
                Path       = $procPath
                RemoteIP   = $remoteIP
                RemotePort = $conn.RemotePort
            }
            
            # Append to CSV
            $logEntry | Export-Csv -Path $logFile -Append -NoTypeInformation -Force
            
            # Print to console in real-time
            Write-Host "[$timestamp] $($procName) ($procId) -> $remoteIP : $($conn.RemotePort)" -ForegroundColor Yellow
        }
    }
    
    Start-Sleep -Milliseconds 500
}