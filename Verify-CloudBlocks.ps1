<#
.SYNOPSIS
    Uses nmap to verify Cloud IP Blocker firewall rules are filtering.
#>
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('AWS','GCP','Azure')]
    [string]$Provider,
    [int]$SampleSize = 3,
    [int]$TopPorts   = 20,
    [int]$TimeoutSec = 30
)

. "$PSScriptRoot\Nmap-Helper.ps1"

 $rulePrefix = switch ($Provider) {
    'AWS'   { 'Blocklist - AWS' }
    'GCP'   { 'Blocklist - GCP' }
    'Azure' { 'Blocklist - Azure' }
}
 $rules = Get-NetFirewallRule -DisplayName "$rulePrefix*" -ErrorAction SilentlyContinue |
         Where-Object { $_.DisplayName -notmatch '\[Out\]' }
if (-not $rules) { Write-Host "[-] No rules found for $Provider." -ForegroundColor Red; exit 1 }

 $sampleIPs = @()
foreach ($r in ($rules | Select-Object -First $SampleSize)) {
    $af = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
    foreach ($cidr in $af.RemoteAddress) {
        if ($cidr -match '^\d+\.\d+\.\d+\.\d+') {
            $sampleIPs += [PSCustomObject]@{ CIDR=$cidr; SampleIP=($cidr -split '/')[0] }
            break
        }
    }
}

Write-Host "[*] Verifying $Provider blocklist with $($sampleIPs.Count) sample IPs..." -ForegroundColor Cyan
 $allGood = $true
foreach ($s in $sampleIPs) {
    Write-Host "`n--- Scanning $($s.SampleIP) (from $($s.CIDR)) ---" -ForegroundColor Cyan
    $r = Invoke-Nmap -Targets $s.SampleIP -TopPorts $TopPorts -HostTimeoutSec $TimeoutSec -ConnectScan
    if (-not $r) { Write-Host "    No result." -ForegroundColor Yellow; continue }
    $open     = @($r.Ports | Where-Object { $_.State -eq 'open' })
    $filtered = @($r.Ports | Where-Object { $_.State -eq 'filtered' })
    $closed   = @($r.Ports | Where-Object { $_.State -eq 'closed' })
    Write-Host "    Status   : $($r.Status)" -ForegroundColor Yellow
    Write-Host "    Open     : $($open.Count)"     -ForegroundColor $(if($open.Count){'Red'}else{'Green'})
    Write-Host "    Filtered : $($filtered.Count)" -ForegroundColor Green
    Write-Host "    Closed   : $($closed.Count)"   -ForegroundColor Yellow
    if ($open.Count -gt 0) {
        $allGood = $false
        Write-Host "    [!] BLOCK IS LEAKING - open ports detected!" -ForegroundColor Red
        $open | ForEach-Object { Write-Host "        $($_.Port)/$($_.Proto) $($_.Service) $($_.Product) $($_.Version)" -ForegroundColor Red }
    } elseif ($filtered.Count -gt 0 -and $closed.Count -eq 0) {
        Write-Host "    [OK] Block verified (ports filtered)." -ForegroundColor Green
    } else {
        Write-Host "    [?] Inconclusive (host may simply be down)." -ForegroundColor Yellow
    }
}
if ($allGood) { Write-Host "`n[OK] All samples verified." -ForegroundColor Green; exit 0 }
else          { Write-Host "`n[!] One or more samples showed open ports!" -ForegroundColor Red; exit 2 }