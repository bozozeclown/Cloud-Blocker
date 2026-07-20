# Must be Admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host 'Run as Administrator!' -ForegroundColor Red; exit 1
}

Write-Host "[1/4] Blocking Vortex IP (52.168.112.66) in Windows Firewall..." -ForegroundColor Cyan
# We use a distinct prefix so it doesn't get cleaned up by the Cloud blocklist uninstaller
 $ip = '52.168.112.66'
New-NetFirewallRule -DisplayName "Block MS Telemetry Vortex IP" -Direction Outbound -Action Block -RemoteAddress $ip -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Block MS Telemetry Vortex IP [In]" -Direction Inbound -Action Block -RemoteAddress $ip -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null

Write-Host "[2/4] Nuking the DiagTrack (Connected User Experiences) service..." -ForegroundColor Cyan
# DiagTrack is the service that physically opens the socket to Vortex
Stop-Service -Name DiagTrack -Force -ErrorAction SilentlyContinue
Set-Service -Name DiagTrack -StartupType Disabled -ErrorAction SilentlyContinue

Write-Host "[3/4] Setting OS Telemetry to 'Security Only' (0) via Registry..." -ForegroundColor Cyan
 $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
Set-ItemProperty -Path $path -Name 'AllowTelemetry' -Value 0 -Type DWord -Force

Write-Host "[4/4] Blocking telemetry DNS domains in the hosts file..." -ForegroundColor Cyan
# As a final failsafe against DoH (DNS over HTTPS) bypassing local rules
 $hostsPath = "$env:windir\System32\drivers\etc\hosts"
 $domains = @(
    "vortex.data.microsoft.com",
    "events.data.microsoft.com",
    "pipe.aria.microsoft.com",
    "mobile.events.data.microsoft.com"
)
 $currentHosts = Get-Content $hostsPath -ErrorAction SilentlyContinue
foreach ($domain in $domains) {
    if ($currentHosts -notcontains "0.0.0.0 $domain") {
        Add-Content -Path $hostsPath -Value "0.0.0.0 $domain"
    }
}

Write-Host "`nVortex tunnel severed. The parasitic connection is dead." -ForegroundColor Green