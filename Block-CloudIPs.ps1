<#
.SYNOPSIS
    Multi-Provider Cloud IP Blocker Engine — Clean switch-based architecture.
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('AWS', 'GCP', 'Azure')]
    [string]$Provider,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('Block', 'Unblock')]
    [string]$Action = 'Block'
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

 $BATCH_SIZE  = 1000
 $SCRIPT_DIR  = $PSScriptRoot
 $LOGFILE     = Join-Path $SCRIPT_DIR "cloud-blocklist-$Provider.log"
 $STATEFILE   = Join-Path $SCRIPT_DIR "cloud-blocklist-$Provider.state"
 $ERROR_FILE  = Join-Path $SCRIPT_DIR "cloud-blocklist-$Provider-error.txt"
 $TEMP_JSON   = Join-Path $SCRIPT_DIR "$Provider-temp.json"
 $CIDR_REGEX  = '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
 $TASK_NAME   = "Cloud IP Blocklist - $Provider"

 $Config = @{
    AWS   = @{ RulePrefix = 'Blocklist - AWS' }
    GCP   = @{ RulePrefix = 'Blocklist - GCP' }
    Azure = @{ RulePrefix = 'Blocklist - Azure' }
}

 $ProviderConfig = $Config[$Provider]
 $HEADERS = @{ "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" }

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timestamp][$Level] $Message"
    Add-Content -Path $LOGFILE -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue
    if ($Level -eq 'ERROR') { Write-Host $entry -ForegroundColor Red }
    elseif ($Level -eq 'WARN') { Write-Host $entry -ForegroundColor Yellow }
    else { Write-Host $entry }
}

# --- ACTION: UNBLOCK ---
if ($Action -eq 'Unblock') {
    Write-Host "[*] Removing firewall rules for $Provider..." -ForegroundColor Cyan
    Get-NetFirewallRule -DisplayName "$($ProviderConfig.RulePrefix)*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Host "[*] Removing scheduled task..." -ForegroundColor Cyan
    Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "[*] Cleaning up state files..." -ForegroundColor Cyan
    Remove-Item $STATEFILE, $LOGFILE, $ERROR_FILE -Force -ErrorAction SilentlyContinue
    Write-Host "[OK] $Provider has been unblocked and uninstalled." -ForegroundColor Green
    exit 0
}

# --- ACTION: BLOCK ---
try {
    if (Test-Path $ERROR_FILE) { Remove-Item $ERROR_FILE -Force }
    if (Test-Path $TEMP_JSON) { Remove-Item $TEMP_JSON -Force }

    Write-Log "=================================================="
    Write-Log "Cloud IP Blocklist - Provider: $Provider - Check Started"

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
    if (-not $isAdmin) { Write-Log "ERROR: Must be run as Administrator." 'ERROR'; exit 1 }

    # --- Switch 1: URL Resolution ---
    $targetUrl = ""
    $useProxy = $false

    switch ($Provider) {
        'AWS' { 
            $targetUrl = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
            $useProxy = $true 
        }
        'GCP' { 
            $targetUrl = 'https://www.gstatic.com/ipranges/goog.json'
            $useProxy = $true 
        }
        'Azure' {
            Write-Log "Resolving current Azure download URL directly from Microsoft..."
            $confirmationPage = Invoke-WebRequest -Uri 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519' -TimeoutSec 30 -UseBasicParsing -Headers $HEADERS -ErrorAction Stop
            $match = [regex]::Match($confirmationPage.Content, 'href="(https://download\.microsoft\.com/download/[^"]+\.json)"')
            if ($match.Success) {
                $targetUrl = $match.Groups[1].Value
                Write-Log "Found live Azure URL: $targetUrl"
            } else { Write-Log "Failed to scrape URL dynamically." 'ERROR'; exit 1 }
            $useProxy = $false
        }
    }

    if ($useProxy) {
        $targetUrl = "https://r.jina.ai/$targetUrl"
        Write-Log "Fetching $Provider IP ranges via blind proxy..."
    } else {
        Write-Log "Fetching $Provider IP ranges directly..."
    }

    $timeout = if ($Provider -eq 'Azure') { 180 } else { 60 }
    Invoke-WebRequest -Uri $targetUrl -OutFile $TEMP_JSON -TimeoutSec $timeout -UseBasicParsing -Headers $HEADERS -ErrorAction Stop

    if (-not (Test-Path $TEMP_JSON) -or (Get-Item $TEMP_JSON).Length -lt 1KB) { Write-Log "Download failed or file is too small." 'ERROR'; exit 1 }
    
    $fileSizeMB = [math]::Round((Get-Item $TEMP_JSON).Length / 1MB, 2)
    Write-Log "Downloaded successfully ($fileSizeMB MB). Parsing JSON..."

    $rawContent = Get-Content $TEMP_JSON -Raw -Encoding UTF8

    if ($useProxy -and $rawContent -notmatch '^\s*\{') {
        $start = $rawContent.IndexOf('{')
        $end = $rawContent.LastIndexOf('}')
        if ($start -ge 0 -and $end -gt $start) { $rawContent = $rawContent.Substring($start, $end - $start + 1) }
    }

    $data = $rawContent | ConvertFrom-Json -ErrorAction Stop

    # --- Switch 2: JSON Parsing ---
    $currentToken = $null
    $ipv4Cidrs = @()

    switch ($Provider) {
        'AWS' { 
            $currentToken = $data.syncToken
            $ipv4Cidrs = $data.prefixes.ip_prefix 
        }
        'GCP' { 
            $currentToken = $data.syncToken
            $ipv4Cidrs = $data.prefixes.ipv4Prefix 
        }
        'Azure' { 
            $currentToken = $data.changeNumber
            $ipv4Cidrs = $data.values.properties.addressPrefixes 
        }
    }

    if (-not $currentToken -or $ipv4Cidrs.Count -eq 0) { Write-Log "Failed to parse $Provider data or no IPs found." 'ERROR'; exit 1 }

    # --- Strict Sanitization ---
    $rawCount = $ipv4Cidrs.Count
    $ipv4Cidrs = $ipv4Cidrs | Where-Object { $_ -match $CIDR_REGEX } | Sort-Object -Unique
    $sanitizedCount = $ipv4Cidrs.Count

    if ($rawCount -ne $sanitizedCount) { Write-Log "Sanitization: Dropped $($rawCount - $sanitizedCount) malformed/IPv6 entries." 'WARN' }
    if ($sanitizedCount -eq 0) { Write-Log "Sanitization failed: No valid IPv4 CIDRs remaining." 'ERROR'; exit 1 }

    $totalIps = $ipv4Cidrs.Count

    # --- Smart Update Check ---
    if (Test-Path $STATEFILE) {
        $lastToken = (Get-Content $STATEFILE -Raw).Trim()
        if ($lastToken -eq $currentToken.ToString().Trim()) {
            $rulesExist = Get-NetFirewallRule -DisplayName "$($ProviderConfig.RulePrefix)*" -ErrorAction SilentlyContinue
            if ($rulesExist) { Write-Log "Token ($currentToken) unchanged and rules exist. Nothing to do."; exit 0 }
        }
    }

    Write-Log "New updates found (Token: $currentToken). Rebuilding firewall rules..."
    Get-NetFirewallRule -DisplayName "$($ProviderConfig.RulePrefix)*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

    $totalBatches = [math]::Ceiling($totalIps / $BATCH_SIZE)
    Write-Log "Creating $totalBatches firewall rule batch(es)..."

    for ($b = 0; $b -lt $totalBatches; $b++) {
        $start = $b * $BATCH_SIZE
        $end   = [Math]::Min($start + $BATCH_SIZE - 1, $totalIps - 1)
        $batch = $ipv4Cidrs[$start..$end]
        $batchNum = $b + 1
        $name = "$($ProviderConfig.RulePrefix) ($batchNum/$totalBatches)"

        try {
            New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Block -RemoteAddress $batch -Profile Any -Enabled True -ErrorAction Stop | Out-Null
            New-NetFirewallRule -DisplayName "$name [Out]" -Direction Outbound -Action Block -RemoteAddress $batch -Profile Any -Enabled True -ErrorAction Stop | Out-Null
            Write-Log "  [OK] Batch $batchNum done."
        } catch { Write-Log "Failed to create batch $batchNum : $_" 'ERROR' }
    }

    Set-Content -Path $STATEFILE -Value $currentToken -Encoding UTF8
    Write-Log "Update complete. Blocked $totalIps CIDRs for $Provider."

} catch {
    Write-Log "Fatal error: $_" 'ERROR'
    $_ | Out-File -FilePath $ERROR_FILE -Encoding UTF8 -ErrorAction SilentlyContinue
    exit 1
} finally {
    if (Test-Path $TEMP_JSON) { Remove-Item $TEMP_JSON -Force -ErrorAction SilentlyContinue }
}