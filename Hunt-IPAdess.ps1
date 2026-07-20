# The IP you want to hunt
 $targetIP = "155.102.44.38"

Write-Host "Hunting for connections to $targetIP... Press Ctrl+C to stop." -ForegroundColor Cyan

while ($true) {
    # Check all active TCP connections
    $connections = Get-NetTCPConnection -RemoteAddress $targetIP -ErrorAction SilentlyContinue
    
    if ($connections) {
        foreach ($conn in $connections) {
            $pid = $conn.OwningProcess
            if ($pid) {
                # Get the process details
                $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                $path = $null
                if ($proc) {
                    try {
                        $path = $proc.Path
                    } catch {}
                }

                Write-Host "`n[!!!] CONNECTION FOUND !!!" -ForegroundColor Red
                Write-Host "     Process ID  : $pid" -ForegroundColor Yellow
                Write-Host "     Process Name: $($proc.ProcessName)" -ForegroundColor Yellow
                Write-Host "     Executable  : $path" -ForegroundColor Yellow
                Write-Host "     Local Port  : $($conn.LocalPort)" -ForegroundColor Yellow
                Write-Host "     State       : $($conn.State)" -ForegroundColor Yellow
                Write-Host "-----------------------------------" -ForegroundColor Cyan
            }
        }
    }
    
    # Check every half second so we don't miss quick connections
    Start-Sleep -Milliseconds 500
}