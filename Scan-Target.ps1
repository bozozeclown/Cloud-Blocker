param(
    [Parameter(Mandatory)][string]$Target,
    [int]$TopPorts = 100,
    [string[]]$Proxies = @(),
    [switch]$CheckProxies,
    [switch]$OsDetect,
    [switch]$ConnectScan
)
. "$PSScriptRoot\Nmap-Helper.ps1"

if ($CheckProxies) {
    Write-Host "[*] Scanning $Target for open proxies..." -ForegroundColor Cyan
    # Ports 80, 3128, 8080, 1080. Uses NSE script http-open-proxy.
    $r = Invoke-Nmap -Targets $Target -ConnectScan -ServiceScan -Ports 80,3128,8080,1080,8443 -HostTimeoutSec 60 -ExtraArgs @('--script', 'http-open-proxy,socks-open-proxy') -Proxies $Proxies
} else {
    Write-Host "[*] Scanning $Target..." -ForegroundColor Cyan
    $r = Invoke-Nmap -Targets $Target -ServiceScan -OsDetect:$OsDetect -ConnectScan:$ConnectScan -TopPorts $TopPorts -HostTimeoutSec 90 -Proxies $Proxies
}

if (-not $r) { 
    Write-Host "No data or nmap not found. (Proxy scanning requires nmap installed)." -ForegroundColor Yellow
    exit 1 
}

 $r | Format-List Host,Hostname,Status,OS
 $r.Ports | Where-Object { $_.State -eq 'open' } | Format-Table Port,Proto,Service,Product,Version -AutoSize