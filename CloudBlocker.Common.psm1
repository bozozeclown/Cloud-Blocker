<#
    CloudBlocker.Common.psm1
    Shared helpers for the Cloud Blocker toolkit. PowerShell 5.1+.

    Design goals (reliability hardening):
      * All firewall rules live in ONE firewall group ("CloudBlocker") so removal
        is atomic and always succeeds, regardless of rule naming drift.
      * Connectivity canary + automatic rollback: if applying a block breaks
        outbound connectivity, the block is reverted automatically.
      * Pending/committed flag files so a crashed/interrupted apply is detected
        and reverted by the guard task.
      * Preflight safety filters: private / loopback / link-local / multicast
        ranges, and absurdly broad prefixes, are never blocked.
#>

$script:CBRoot       = $PSScriptRoot
$script:CBConfigPath = Join-Path $script:CBRoot 'cloudblocker.config.json'
$script:CBStateDir   = Join-Path $script:CBRoot 'state'
$script:CBLogDir     = Join-Path $script:CBRoot 'logs'
$script:CBGroup      = 'CloudBlocker'

# Private / special-use IPv4 ranges that must never be blocked.
$script:CBPrivateRanges = @(
    [pscustomobject]@{ Prefix = '0.0.0.0';      Len = 8  },
    [pscustomobject]@{ Prefix = '10.0.0.0';     Len = 8  },
    [pscustomobject]@{ Prefix = '100.64.0.0';   Len = 10 },
    [pscustomobject]@{ Prefix = '127.0.0.0';    Len = 8  },
    [pscustomobject]@{ Prefix = '169.254.0.0';  Len = 16 },
    [pscustomobject]@{ Prefix = '172.16.0.0';   Len = 12 },
    [pscustomobject]@{ Prefix = '192.0.0.0';    Len = 24 },
    [pscustomobject]@{ Prefix = '192.0.2.0';    Len = 24 },
    [pscustomobject]@{ Prefix = '192.88.99.0';  Len = 24 },
    [pscustomobject]@{ Prefix = '192.168.0.0';  Len = 16 },
    [pscustomobject]@{ Prefix = '198.18.0.0';   Len = 15 },
    [pscustomobject]@{ Prefix = '198.51.100.0'; Len = 24 },
    [pscustomobject]@{ Prefix = '203.0.113.0';  Len = 24 },
    [pscustomobject]@{ Prefix = '224.0.0.0';    Len = 4  },
    [pscustomobject]@{ Prefix = '240.0.0.0';    Len = 4  }
)

# Precomputed byte arrays for fast prefix comparison (avoids per-CIDR parsing).
$script:CBPrivateRangeBytes = @($script:CBPrivateRanges | ForEach-Object {
    [pscustomobject]@{ Bytes = ([System.Net.IPAddress]::Parse($_.Prefix)).GetAddressBytes(); Len = [int]$_.Len }
})

function Initialize-CBDirs {
    foreach ($d in @($script:CBStateDir, $script:CBLogDir)) {
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }
}

function Get-CBConfig {
    Initialize-CBDirs
    if (-not (Test-Path -LiteralPath $script:CBConfigPath)) { return $null }
    try {
        return (Get-Content -LiteralPath $script:CBConfigPath -Raw | ConvertFrom-Json)
    } catch {
        Write-CBLog "Failed to parse config '$script:CBConfigPath': $_" 'ERROR'
        return $null
    }
}

function Write-CBLog {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Level = 'INFO',
        [string]$Provider = ''
    )
    Initialize-CBDirs
    $ts  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $tag = if ($Provider) { "[$Provider]" } else { '' }
    $line = "[$ts][$Level]$tag $Message"
    Add-Content -LiteralPath (Join-Path $script:CBLogDir 'cloudblocker.log') -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    switch ($Level) {
        'ERROR'    { Write-Host $line -ForegroundColor Red }
        'CRITICAL' { Write-Host $line -ForegroundColor Magenta }
        'WARN'     { Write-Host $line -ForegroundColor Yellow }
        'OK'       { Write-Host $line -ForegroundColor Green }
        default    { Write-Host $line }
    }
}

function Get-CBEnabledProviders {
    param($Config)
    $out = @()
    if ($Config -and $Config.providers) {
        foreach ($p in $Config.providers.PSObject.Properties) {
            if ($p.Value -and $p.Value.enabled) { $out += $p.Name }
        }
    }
    return $out
}

# ---------------------------------------------------------------------------
# Connectivity canary
# ---------------------------------------------------------------------------

function Test-CBTcp {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [int]$Port = 443,
        [int]$TimeoutMs = 3000
    )
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($Address, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            $client.EndConnect($iar)
            return $true
        }
        return $false
    } catch {
        return $false
    } finally {
        try { $client.Close() } catch { }
    }
}

function Test-CBConnectivity {
    param($Config)

    $canaries = @()
    if ($Config -and $Config.canaries) { $canaries = @($Config.canaries) }
    if ($canaries.Count -eq 0) {
        $canaries = @(
            [pscustomobject]@{ ip = '1.1.1.1'; port = 443 },
            [pscustomobject]@{ ip = '9.9.9.9'; port = 443 },
            [pscustomobject]@{ ip = '8.8.8.8'; port = 53 }
        )
    }

    $up = 0
    $detail = @()
    foreach ($c in $canaries) {
        $port = 443
        if ($c.PSObject.Properties['port'] -and $c.port) { $port = [int]$c.port }
        $ok = Test-CBTcp -Address $c.ip -Port $port -TimeoutMs 3000
        if ($ok) { $up++ }
        $detail += ("{0}:{1}={2}" -f $c.ip, $port, $(if ($ok) { 'UP' } else { 'DOWN' }))
    }

    $gw = $null
    try {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($route) { $gw = $route.NextHop }
    } catch { }

    $gwUp = $null
    if ($gw -and $gw -ne '0.0.0.0') {
        $gwUp = [bool](Test-Connection -ComputerName $gw -Count 1 -Quiet -ErrorAction SilentlyContinue)
    }

    # Healthy = at least one external canary reachable. Gateway is advisory only
    # (ICMP can be filtered even when the network is fine).
    $healthy = ($up -ge 1)

    return [pscustomobject]@{
        Healthy    = $healthy
        CanaryUp   = $up
        CanaryMax  = $canaries.Count
        Gateway    = $gw
        GatewayUp  = $gwUp
        Detail     = ($detail -join ', ')
        Timestamp  = (Get-Date)
    }
}

function Wait-CBNetwork {
    param(
        $Config,
        [int]$TimeoutSeconds = 180,
        [int]$PollSeconds = 5
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $r = Test-CBConnectivity -Config $Config
        if ($r.Healthy) {
            Write-CBLog "Network ready ($($r.Detail))." 'INFO'
            return $true
        }
        Write-CBLog "Waiting for network ($($r.Detail))..." 'WARN'
        Start-Sleep -Seconds $PollSeconds
    }
    Write-CBLog "Network not ready after $TimeoutSeconds s." 'ERROR'
    return $false
}

# ---------------------------------------------------------------------------
# Fetch + parse provider IP ranges
# ---------------------------------------------------------------------------

function Invoke-CBWebFetch {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [int]$MaxRetries = 3,
        [int]$TimeoutSec = 60
    )
    $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

    $attempt = 0
    $lastErr = ''
    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec $TimeoutSec -Headers @{ 'User-Agent' = $ua } -ErrorAction Stop
            $content = $resp.Content
            if ($content -is [byte[]]) { $content = [System.Text.Encoding]::UTF8.GetString($content) }
            elseif ($content -isnot [string]) { $content = [string]$content }
            if ($content -and $content.Length -gt 32) { return $content }
            $lastErr = "response too small ($(if ($content) { $content.Length } else { 0 }) bytes)"
        } catch {
            $lastErr = "$_"
            Write-CBLog "Fetch attempt $attempt/$MaxRetries failed: $lastErr" 'WARN'
        }
        Start-Sleep -Seconds (2 * $attempt)
    }
    throw "Failed to fetch '$Url' after $MaxRetries attempts: $lastErr"
}

function Resolve-CBProviderUrl {
    param(
        [Parameter(Mandatory = $true)][string]$Provider,
        $Config
    )
    $pconf = $null
    if ($Config -and $Config.providers -and $Config.providers.PSObject.Properties[$Provider]) {
        $pconf = $Config.providers.PSObject.Properties[$Provider].Value
    }
    if ($pconf -and $pconf.url) { return $pconf.url }

    switch ($Provider) {
        'AWS' { return 'https://ip-ranges.amazonaws.com/ip-ranges.json' }
        'GCP' { return 'https://www.gstatic.com/ipranges/cloud.json' }
        'Azure' {
            Write-CBLog "Resolving current Azure Service Tags download URL..." 'INFO' $Provider
            $page = Invoke-CBWebFetch -Url 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519' -TimeoutSec 30
            $m = [regex]::Match($page, 'href="(https://download\.microsoft\.com/download/[^"]+\.json)"')
            if ($m.Success) { return $m.Groups[1].Value }
            throw 'Could not resolve the Azure download URL from the confirmation page.'
        }
    }
    throw "No download URL configured for provider '$Provider'."
}

function ConvertFrom-CBJson {
    <#
        PS 5.1's ConvertFrom-Json uses JavaScriptSerializer with a 2 MB MaxJsonLength,
        which fails on the multi-MB Azure Service Tags file. This returns the parsed
        tree (Dictionary / array / primitive) with no size limit.
    #>
    param([Parameter(Mandatory = $true)][string]$Json)
    try {
        Add-Type -AssemblyName System.Web.Extensions -ErrorAction SilentlyContinue
        $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $serializer.MaxJsonLength = [int]::MaxValue
        $serializer.RecursionLimit = 1024
        return $serializer.DeserializeObject($Json)
    } catch {
        return ($Json | ConvertFrom-Json -ErrorAction Stop)
    }
}

function Get-CBJField {
    # Safe field access that works for both Dictionary (JavaScriptSerializer) and PSCustomObject.
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) {
        $has = $false
        try { $has = [bool]$Obj.ContainsKey($Name) } catch { $has = $false }
        if ($has) { return $Obj[$Name] } else { return $null }
    }
    try { return $Obj.$Name } catch { return $null }
}

function Get-CBProviderCidrs {
    param(
        [Parameter(Mandatory = $true)][string]$Provider,
        $Config,
        [int]$MaxRetries = 3
    )
    $pconf = $null
    if ($Config -and $Config.providers -and $Config.providers.PSObject.Properties[$Provider]) {
        $pconf = $Config.providers.PSObject.Properties[$Provider].Value
    }
    if ($pconf -and ($pconf.PSObject.Properties['enabled']) -and (-not $pconf.enabled)) {
        throw "Provider '$Provider' is disabled in config."
    }

    $url  = Resolve-CBProviderUrl -Provider $Provider -Config $Config
    $raw  = Invoke-CBWebFetch -Url $url -MaxRetries $MaxRetries -TimeoutSec $(if ($Provider -eq 'Azure') { 180 } else { 60 })
    $data = ConvertFrom-CBJson -Json $raw

    $token = $null
    $list  = New-Object System.Collections.Generic.List[string]
    switch ($Provider) {
        'AWS' {
            $token = Get-CBJField $data 'syncToken'
            foreach ($x in @(Get-CBJField $data 'prefixes')) { [void]$list.Add([string](Get-CBJField $x 'ip_prefix')) }
        }
        'GCP' {
            $token = Get-CBJField $data 'syncToken'
            foreach ($x in @(Get-CBJField $data 'prefixes')) { [void]$list.Add([string](Get-CBJField $x 'ipv4Prefix')) }
        }
        'Azure' {
            $token = Get-CBJField $data 'changeNumber'
            foreach ($v in @(Get-CBJField $data 'values')) {
                $props = Get-CBJField $v 'properties'
                if ($props) { foreach ($pfx in @(Get-CBJField $props 'addressPrefixes')) { [void]$list.Add([string]$pfx) } }
            }
        }
        default {
            throw "No parser implemented for provider '$Provider'."
        }
    }

    # Drop null/blank entries (IPv6-only rows, missing properties, whitespace).
    $list = @($list | ForEach-Object { if ($null -ne $_) { "$_".Trim() } } | Where-Object { $_ -ne '' -and $null -ne $_ })

    return [pscustomobject]@{
        Provider = $Provider
        Url      = $url
        Token    = "$token"
        Cidrs    = $list
    }
}

# ---------------------------------------------------------------------------
# CIDR sanitisation + safety filters
# ---------------------------------------------------------------------------

function Test-CBIsPrivate {
    param([Parameter(Mandatory = $true)][string]$Cidr)
    $parts = $Cidr -split '/'
    if ($parts.Count -ne 2) { return $true }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$ip)) { return $true }
    if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $true }
    $bytes = $ip.GetAddressBytes()

    foreach ($r in $script:CBPrivateRangeBytes) {
        $rb = $r.Bytes
        $plen = [int]$r.Len
        $match = $true
        for ($i = 0; $i -lt 4; $i++) {
            $bits = [Math]::Min(8, [Math]::Max(0, $plen - ($i * 8)))
            if ($bits -le 0) { break }
            $mask = if ($bits -ge 8) { 255 } else { [int](256 - [Math]::Pow(2, 8 - $bits)) }
            if (($bytes[$i] -band $mask) -ne ($rb[$i] -band $mask)) { $match = $false; break }
        }
        if ($match) { return $true }
    }
    return $false
}

function ConvertTo-CBCidrs {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Cidrs,
        [string[]]$ExcludeCidrs = @(),
        [int]$MinPrefixLength = 8
    )
    $cidrRe = '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$'
    $stats = [ordered]@{ input = 0; invalid = 0; private = 0; tooBroad = 0; excluded = 0; kept = 0 }
    $seen = @{}
    $kept = New-Object System.Collections.Generic.List[string]
    $exclude = @{}
    foreach ($e in $ExcludeCidrs) { if ($e) { $exclude[$e.Trim()] = $true } }

    foreach ($c in $Cidrs) {
        $stats.input++
        if (-not $c) { $stats.invalid++; continue }
        $c = $c.Trim()
        $m = [regex]::Match($c, $cidrRe)
        if (-not $m.Success) { $stats.invalid++; continue }
        $octets = @([int]$m.Groups[1].Value, [int]$m.Groups[2].Value, [int]$m.Groups[3].Value, [int]$m.Groups[4].Value)
        if (($octets | Where-Object { $_ -gt 255 }).Count -gt 0) { $stats.invalid++; continue }
        $plen = [int]$m.Groups[5].Value
        if ($plen -gt 32) { $stats.invalid++; continue }
        if ($plen -lt $MinPrefixLength) { $stats.tooBroad++; continue }
        if (Test-CBIsPrivate -Cidr $c) { $stats.private++; continue }
        if ($exclude.ContainsKey($c)) { $stats.excluded++; continue }
        if ($seen.ContainsKey($c)) { continue }
        $seen[$c] = $true
        [void]$kept.Add($c)
        $stats.kept++
    }
    return [pscustomobject]@{ Cidrs = $kept.ToArray(); Stats = $stats }
}

# ---------------------------------------------------------------------------
# Firewall rule operations (group-based = atomic + reliable removal)
# ---------------------------------------------------------------------------

function Get-CBRules {
    param([string]$Provider = '')
    $rules = @(Get-NetFirewallRule -Group $script:CBGroup -ErrorAction SilentlyContinue)
    if ($Provider) {
        $rules = @($rules | Where-Object { $_.DisplayName -like "CB:$Provider (*" })
    }
    return $rules
}

function Remove-CBProviderRules {
    param([Parameter(Mandatory = $true)][string]$Provider)
    $rules = Get-CBRules -Provider $Provider
    if ($rules.Count -gt 0) {
        $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }
    return $rules.Count
}

function Remove-CBAllRules {
    $rules = @(Get-NetFirewallRule -Group $script:CBGroup -ErrorAction SilentlyContinue)
    if ($rules.Count -gt 0) {
        $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }
    return $rules.Count
}

function New-CBProviderRules {
    param(
        [Parameter(Mandatory = $true)][string]$Provider,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Cidrs,
        [int]$BatchSize = 1000
    )
    $total = $Cidrs.Count
    if ($total -eq 0) { return 0 }
    $totalBatches = [int][Math]::Ceiling($total / $BatchSize)
    for ($b = 0; $b -lt $totalBatches; $b++) {
        $start = $b * $BatchSize
        $end   = [Math]::Min($start + $BatchSize - 1, $total - 1)
        $batch = @($Cidrs[$start..$end])
        $name  = "CB:$Provider ($($b + 1)/$totalBatches)"
        $desc  = "CloudBlocker $Provider (managed - do not edit by hand)"
        New-NetFirewallRule -DisplayName $name        -Group $script:CBGroup -Direction Inbound  -Action Block -RemoteAddress $batch -Profile Any -Enabled True -Description $desc -ErrorAction Stop | Out-Null
        New-NetFirewallRule -DisplayName "$name [Out]" -Group $script:CBGroup -Direction Outbound -Action Block -RemoteAddress $batch -Profile Any -Enabled True -Description $desc -ErrorAction Stop | Out-Null
    }
    return $totalBatches
}

# ---------------------------------------------------------------------------
# Flag files (pending / committed) - crash detection for the guard
# ---------------------------------------------------------------------------

function Get-CBFlagPath { param([string]$Name) return (Join-Path $script:CBStateDir "$Name.json") }

function Set-CBFlag {
    param([Parameter(Mandatory = $true)][string]$Name, [hashtable]$Data = @{})
    Initialize-CBDirs
    $Data['ts'] = (Get-Date).ToString('o')
    ($Data | ConvertTo-Json) | Set-Content -LiteralPath (Get-CBFlagPath $Name) -Encoding UTF8
}

function Test-CBFlag { param([string]$Name) return (Test-Path -LiteralPath (Get-CBFlagPath $Name)) }

function Get-CBFlag {
    param([string]$Name)
    if (Test-CBFlag $Name) {
        try { return (Get-Content -LiteralPath (Get-CBFlagPath $Name) -Raw | ConvertFrom-Json) } catch { return $null }
    }
    return $null
}

function Clear-CBFlag {
    param([string]$Name)
    Remove-Item -LiteralPath (Get-CBFlagPath $Name) -Force -ErrorAction SilentlyContinue
}

function Get-CBStatus {
    param($Config)
    $rules = @(Get-NetFirewallRule -Group $script:CBGroup -ErrorAction SilentlyContinue)
    $byProvider = [ordered]@{}
    foreach ($r in $rules) {
        if ($r.DisplayName -match '^CB:([^ ]+) \(') {
            $p = $Matches[1]
            if (-not $byProvider.Contains($p)) { $byProvider[$p] = 0 }
            $byProvider[$p]++
        }
    }
    return [pscustomobject]@{
        Group        = $script:CBGroup
        RuleCount    = $rules.Count
        ByProvider   = $byProvider
        Pending      = @(Get-ChildItem -LiteralPath $script:CBStateDir -Filter 'pending-*.json' -ErrorAction SilentlyContinue | ForEach-Object { $_.BaseName })
        Connectivity = Test-CBConnectivity -Config $Config
    }
}

Export-ModuleMember -Function *
