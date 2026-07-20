<#
.SYNOPSIS
    Shared helper: locate nmap, run scans, parse XML.
#>

function Find-Nmap {
    $candidates = @(
        'nmap.exe',
        "$env:ProgramFiles\Nmap\nmap.exe",
        "${env:ProgramFiles(x86)}\Nmap\nmap.exe",
        'C:\Program Files\Nmap\nmap.exe',
        'C:\Program Files (x86)\Nmap\nmap.exe'
    )
    foreach ($c in $candidates) {
        $resolved = Get-Command $c -ErrorAction SilentlyContinue
        if ($resolved) { return $resolved.Source }
    }
    throw "nmap.exe not found in PATH or default install locations."
}

function ConvertFrom-NmapXml {
    param([Parameter(Mandatory)][string]$Xml)
    # Strip any leading BOM / whitespace that breaks [xml] cast
    $Xml = $Xml.Trim()
    if (-not $Xml.StartsWith('<?xml') -and -not $Xml.StartsWith('<nmaprun')) {
        $idx = $Xml.IndexOf('<nmaprun')
        if ($idx -gt 0) { $Xml = $Xml.Substring($idx) }
    }
    try { $doc = [xml]$Xml } catch { return $null }

    $hosts = @()
    foreach ($h in $doc.nmaprun.host) {
        $addr = ($h.address | Where-Object { $_.addrtype -eq 'ipv4' }).addr
        $hostname = ($h.hostnames.hostname | Select-Object -First 1).name
        $status   = $h.status.state
        $osGuess  = ($h.os.osmatch | Select-Object -First 1).name

        $ports = @()
        if ($h.ports.port) {
            foreach ($p in $h.ports.port) {
                $ports += [PSCustomObject]@{
                    Port    = [int]$p.portid
                    Proto   = $p.protocol
                    State   = $p.state.state
                    Service = $p.service.name
                    Product = $p.service.product
                    Version = $p.service.version
                    CPE     = $p.service.cpe
                }
            }
        }
        $hosts += [PSCustomObject]@{
            Host=$addr; Hostname=$hostname; Status=$status; OS=$osGuess
            Ports=$ports; Raw=$h
        }
    }
    return $hosts
}

function Invoke-Nmap {
    param(
        [Parameter(Mandatory)][string[]]$Targets,
        [string[]]$ExtraArgs   = @(),
        [int]     $HostTimeoutSec = 120,
        [int]     $MaxRate       = 0,
        [switch]  $ServiceScan,
        [switch]  $OsDetect,
        [switch]  $PingOnly,
        [int]     $TopPorts   = 0,
        [string[]]$Ports      = @(),
        [switch]  $ConnectScan   # -sT (no admin needed)
    )
    $nmap = Find-Nmap
    $nmapArgs = @('-oX', '-')
    if ($PingOnly)   { $nmapArgs += '-sn' } else { $nmapArgs += '-Pn' }
    if ($ConnectScan){ $nmapArgs += '-sT' }
    if ($ServiceScan){ $nmapArgs += '-sV' }
    if ($OsDetect)   { $nmapArgs += '-O'  }
    if ($TopPorts -gt 0)    { $nmapArgs += '--top-ports'; $nmapArgs += "$TopPorts" }
    if ($Ports.Count -gt 0) { $nmapArgs += '-p'; $nmapArgs += ($Ports -join ',') }
    if ($MaxRate -gt 0)     { $nmapArgs += '--max-rate'; $nmapArgs += "$MaxRate" }
    $nmapArgs += '--host-timeout'; $nmapArgs += "${HostTimeoutSec}s"
    $nmapArgs += $ExtraArgs
    $nmapArgs += $Targets

    Write-Verbose "Running: $nmap $($nmapArgs -join ' ')"
    $xmlOut = & $nmap @nmapArgs 2>$null
    if (-not $xmlOut) { return $null }
    ConvertFrom-NmapXml -Xml ($xmlOut -join "`n")
}

function Get-NmapServiceInfo {
    param(
        [Parameter(Mandatory)][string]$IP,
        [int]$TopPorts = 100,
        [int]$TimeoutSec = 60
    )
    Invoke-Nmap -Targets $IP -ServiceScan -TopPorts $TopPorts -HostTimeoutSec $TimeoutSec -ConnectScan
}

function Invoke-PsPortScan {
    param(
        [Parameter(Mandatory)][string]$IP,
        [int[]]$Ports = (21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443),
        [int]$TimeoutMs = 600
    )
    $openPorts = @()
    foreach ($port in $Ports) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $tcp.BeginConnect($IP, $port, $null, $null)
            $success = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
            if ($success -and $tcp.Connected) {
                $openPorts += [PSCustomObject]@{
                    Port=$port; Proto='tcp'; State='open'; Service='unknown'; Product='PsScan'; Version=''
                }
            }
        } catch {} finally { $tcp.Close() }
    }
    return [PSCustomObject]@{ Host=$IP; Hostname=''; Status='up'; OS=''; Ports=$openPorts; Raw=$null }
}

function Get-ScanResult {
    param(
        [Parameter(Mandatory)][string]$IP,
        [int]$TopPorts = 100,
        [int]$TimeoutSec = 60
    )
    try {
        $nmapPath = Find-Nmap
        return Invoke-Nmap -Targets $IP -ServiceScan -TopPorts $TopPorts -HostTimeoutSec $TimeoutSec -ConnectScan
    } catch {
        Write-Verbose "Nmap not found, falling back to native PowerShell port scan."
        return Invoke-PsPortScan -IP $IP -TimeoutMs 600
    }
}

# Add -Proxies to Invoke-Nmap
function Invoke-Nmap {
    param(
        [Parameter(Mandatory)][string[]]$Targets,
        [string[]]$ExtraArgs   = @(),
        [string[]]$Proxies     = @(),
        [int]     $HostTimeoutSec = 120,
        [int]     $MaxRate       = 0,
        [switch]  $ServiceScan,
        [switch]  $OsDetect,
        [switch]  $PingOnly,
        [int]     $TopPorts   = 0,
        [string[]]$Ports      = @(),
        [switch]  $ConnectScan
    )
    $nmap = Find-Nmap
    $nmapArgs = @('-oX', '-')
    if ($PingOnly)   { $nmapArgs += '-sn' } else { $nmapArgs += '-Pn' }
    if ($ConnectScan){ $nmapArgs += '-sT' }
    if ($ServiceScan){ $nmapArgs += '-sV' }
    if ($OsDetect)   { $nmapArgs += '-O'  }
    if ($TopPorts -gt 0)    { $nmapArgs += '--top-ports'; $nmapArgs += "$TopPorts" }
    if ($Ports.Count -gt 0) { $nmapArgs += '-p'; $nmapArgs += ($Ports -join ',') }
    if ($MaxRate -gt 0)     { $nmapArgs += '--max-rate'; $nmapArgs += "$MaxRate" }
    if ($Proxies.Count -gt 0) {
        $nmapArgs += '--proxies'
        $nmapArgs += ($Proxies -join ',')
    }
    $nmapArgs += '--host-timeout'; $nmapArgs += "${HostTimeoutSec}s"
    $nmapArgs += $ExtraArgs
    $nmapArgs += $Targets

    Write-Verbose "Running: $nmap $($nmapArgs -join ' ')"
    $xmlOut = & $nmap @nmapArgs 2>$null
    if (-not $xmlOut) { return $null }
    ConvertFrom-NmapXml -Xml ($xmlOut -join "`n")
}