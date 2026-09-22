<#
.SYNOPSIS
    Cloud IP Blocker engine - hardened (v2).

.DESCRIPTION
    Blocks inbound/outbound traffic to a cloud provider's published IPv4 ranges
    using a single managed firewall group ("CloudBlocker").

    Reliability guarantees:
      * Waits for a working network before doing anything (fixes boot-time runs).
      * Fetches and sanitises ALL requested providers BEFORE touching the firewall,
        so a failed download never leaves you half-blocked.
      * Creates firewall rules in one reviewable group so unblock is atomic.
      * Runs a connectivity canary after applying. If outbound connectivity dies,
        the block is rolled back automatically (unless -NoRollback).
      * Writes pending/committed flags so an interrupted run is reverted by Guard.
      * Never blocks private/loopback/link-local/multicast ranges.
      * Optional -TrialMinutes schedules an automatic full unblock so a bad block
        cannot outlive the trial window if you forget about it.

.PARAMETER Provider
    AWS | GCP | Azure | Alibaba | ALL

.PARAMETER Action
    Block (default) | Unblock | Verify | Guard

.PARAMETER Force
    Proceed even when the block is larger than maxCidrsWithoutForce.

.PARAMETER TrialMinutes
    Schedule an automatic unblock of everything after this many minutes.

.PARAMETER NoRollback
    Do not auto-revert a block that breaks connectivity (NOT recommended).

.PARAMETER ExcludeCidr
    Extra CIDRs to remove from the block (defence against self-lockout).
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('AWS', 'GCP', 'Azure', 'Alibaba', 'ALL')]
    [string]$Provider,

    [ValidateSet('Block', 'Unblock', 'Verify', 'Guard')]
    [string]$Action = 'Block',

    [switch]$Force,
    [int]$TrialMinutes = 0,
    [switch]$NoRollback,
    [string[]]$ExcludeCidr = @()
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'CloudBlocker.Common.psm1') -Force

$root       = $PSScriptRoot
$scriptPath = Join-Path $root 'Block-CloudIPs.ps1'
$trialTask  = 'CloudBlocker - TrialRollback'

function Get-TargetProviders {
    param([string]$Requested, $Config)
    if ($Requested -eq 'ALL') {
        $enabled = Get-CBEnabledProviders -Config $Config
        # Keep providers that currently have rules too, so ALL can always clean up.
        $withRules = @(Get-NetFirewallRule -Group 'CloudBlocker' -ErrorAction SilentlyContinue |
            ForEach-Object { if ($_.DisplayName -match '^CB:([^ ]+) \(') { $Matches[1] } } | Select-Object -Unique)
        return @(($enabled + $withRules) | Select-Object -Unique)
    }
    return @($Requested)
}

function Register-TrialRollback {
    param([int]$Minutes)
    try {
        Unregister-ScheduledTask -TaskName $trialTask -Confirm:$false -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`" -Provider ALL -Action Unblock"
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $trigger   = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes($Minutes))
        $settings  = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 20)
        Register-ScheduledTask -TaskName $trialTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        Write-CBLog "Trial window armed: full unblock scheduled in $Minutes minute(s) ($trialTask)." 'WARN'
    } catch {
        Write-CBLog "Could not arm trial rollback task: $_" 'WARN'
    }
}

# ---------------------------------------------------------------------------
# Guard: revert interrupted/running blocks that broke connectivity
# ---------------------------------------------------------------------------
if ($Action -eq 'Guard') {
    $config = Get-CBConfig
    $pending = @(Get-ChildItem -LiteralPath (Join-Path $root 'state') -Filter 'pending-*.json' -ErrorAction SilentlyContinue)
    if ($pending.Count -eq 0) {
        Write-CBLog "Guard: no pending applies. Nothing to do." 'INFO'
        exit 0
    }

    $grace = 300
    if ($config -and $config.commitGraceSeconds) { $grace = [int]$config.commitGraceSeconds }
    $conn = Test-CBConnectivity -Config $config

    $rules = @(Get-NetFirewallRule -Group 'CloudBlocker' -ErrorAction SilentlyContinue)
    if (-not $conn.Healthy -and $rules.Count -gt 0) {
        Write-CBLog "Guard: pending apply detected AND connectivity is DOWN ($($conn.Detail)). Rolling back ALL cloud blocks." 'CRITICAL'
        [void](Remove-CBAllRules)
        Get-ChildItem -LiteralPath (Join-Path $root 'state') -Filter 'pending-*.json' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        exit 2
    }

    # Stale pending (engine likely killed mid-apply): revert after the grace period.
    foreach ($f in $pending) {
        $age = ((Get-Date) - $f.LastWriteTime).TotalSeconds
        if ($age -gt $grace) {
            Write-CBLog "Guard: stale pending flag '$($f.Name)' ($([int]$age)s old). Rolling back ALL cloud blocks." 'CRITICAL'
            [void](Remove-CBAllRules)
            Get-ChildItem -LiteralPath (Join-Path $root 'state') -Filter 'pending-*.json' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            exit 2
        }
    }
    Write-CBLog "Guard: pending apply in progress/grace window. Leaving as-is." 'INFO'
    exit 0
}

$config = Get-CBConfig
if (-not $config) { Write-CBLog "Config missing or invalid at '$root\cloudblocker.config.json'." 'ERROR'; exit 1 }
$batchSize = 1000
if ($config.batchSize) { $batchSize = [int]$config.batchSize }
$maxNoForce = 5000
if ($config.maxCidrsWithoutForce) { $maxNoForce = [int]$config.maxCidrsWithoutForce }

Write-CBLog "==== $Action started (Provider=$Provider) ====" 'INFO'

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
if ($Action -eq 'Verify') {
    $status = Get-CBStatus -Config $config
    Write-Host ("Rules in group '{0}': {1}" -f $status.Group, $status.RuleCount)
    foreach ($k in $status.ByProvider.Keys) { Write-Host ("  {0}: {1} rule(s)" -f $k, $status.ByProvider[$k]) }
    if ($status.Pending.Count) { Write-Host ("  PENDING: {0}" -f ($status.Pending -join ', ')) }
    Write-Host ("Connectivity: {0} ({1})" -f $(if ($status.Connectivity.Healthy) { 'HEALTHY' } else { 'DOWN' }), $status.Connectivity.Detail)
    Write-Host ("Gateway: {0} ({1})" -f $status.Connectivity.Gateway, $(if ($status.Connectivity.GatewayUp) { 'up' } else { 'no reply' }))
    exit 0
}

# ---------------------------------------------------------------------------
# Unblock
# ---------------------------------------------------------------------------
if ($Action -eq 'Unblock') {
    $targets = Get-TargetProviders -Requested $Provider -Config $config
    $total = 0
    foreach ($p in $targets) {
        $n = Remove-CBProviderRules -Provider $p
        Clear-CBFlag "pending-$p"
        Clear-CBFlag "committed-$p"
        $total += $n
        Write-CBLog "Unblocked $p ($n rule(s) removed)." 'OK' $p
    }
    Unregister-ScheduledTask -TaskName $trialTask -Confirm:$false -ErrorAction SilentlyContinue
    Write-CBLog "Unblock complete. $total rule(s) removed." 'OK'
    exit 0
}

# ---------------------------------------------------------------------------
# Block
# ---------------------------------------------------------------------------
$targets = Get-TargetProviders -Requested $Provider -Config $config
if ($targets.Count -eq 0) { Write-CBLog "No target providers to block." 'WARN'; exit 0 }

# 1) Network must be up first.
if (-not (Wait-CBNetwork -Config $config -TimeoutSeconds 180)) {
    Write-CBLog "Aborting: no working network. Not touching the firewall." 'ERROR'
    exit 1
}

# 2) Fetch + sanitise everything BEFORE modifying the firewall.
$plan = @()
foreach ($p in $targets) {
    try {
        Write-CBLog "Fetching IP ranges..." 'INFO' $p
        $data = Get-CBProviderCidrs -Provider $p -Config $config
        $excl = @()
        if ($config.extraExcludeCidrs) { $excl += @($config.extraExcludeCidrs) }
        if ($ExcludeCidr) { $excl += @($ExcludeCidr) }
        $sanitised = ConvertTo-CBCidrs -Cidrs @($data.Cidrs | Where-Object { $_ }) -ExcludeCidrs $excl
        $s = $sanitised.Stats
        Write-CBLog ("Parsed {0}: kept {1}, dropped invalid={2} private={3} tooBroad={4} excluded={5} (token {6})." -f `
            $p, $s.kept, $s.invalid, $s.private, $s.tooBroad, $s.excluded, $data.Token) 'INFO' $p
        if ($sanitised.Cidrs.Count -eq 0) { throw "No valid CIDRs for '$p'." }
        $plan += [pscustomobject]@{ Provider = $p; Cidrs = $sanitised.Cidrs; Token = $data.Token }
    } catch {
        Write-CBLog "Fetch/parse FAILED for '$p': $_" 'ERROR' $p
    }
}

if ($plan.Count -eq 0) {
    Write-CBLog "Nothing could be fetched. Existing rules left untouched. Aborting." 'ERROR'
    exit 1
}

$grandTotal = ($plan | ForEach-Object { $_.Cidrs.Count } | Measure-Object -Sum).Sum
if ($grandTotal -gt $maxNoForce -and -not $Force) {
    Write-CBLog "REFUSING: $grandTotal CIDRs exceeds safety limit ($maxNoForce). Blocking this much of the internet will break most services. Re-run with -Force if you are sure." 'ERROR'
    exit 3
}

# 3) Mark pending BEFORE we start changing rules (guard uses this).
foreach ($item in $plan) { Set-CBFlag "pending-$($item.Provider)" @{ provider = $item.Provider; cidrs = $item.Cidrs.Count; pid = $PID } }

# 4) Apply.
$applied = 0
foreach ($item in $plan) {
    try {
        $removed = Remove-CBProviderRules -Provider $item.Provider
        if ($removed -gt 0) { Write-CBLog "Replaced $removed existing rule(s)." 'INFO' $item.Provider }
        $batches = New-CBProviderRules -Provider $item.Provider -Cidrs $item.Cidrs -BatchSize $batchSize
        Write-CBLog "Applied $($item.Cidrs.Count) CIDRs in $batches batch(es) ($($batches * 2) rules)." 'OK' $item.Provider
        $applied++
    } catch {
        Write-CBLog "Failed to apply '$($item.Provider)': $_" 'ERROR' $item.Provider
        Clear-CBFlag "pending-$($item.Provider)"
    }
}

# 5) Canary + automatic rollback.
Start-Sleep -Seconds 3
$conn = Test-CBConnectivity -Config $config
Write-CBLog "Canary after apply: $($conn.Detail) [gateway $($conn.Gateway) $(if($conn.GatewayUp){'up'}else{'no reply'})]" 'INFO'

if (-not $conn.Healthy -and -not $NoRollback) {
    Write-CBLog "CRITICAL: connectivity lost after applying block. Rolling back automatically." 'CRITICAL'
    [void](Remove-CBAllRules)
    foreach ($item in $plan) { Clear-CBFlag "pending-$($item.Provider)" }
    exit 2
}

# 6) Commit.
foreach ($item in $plan) {
    $ruleCount = @(Get-CBRules -Provider $item.Provider).Count
    Set-CBFlag "committed-$($item.Provider)" @{ provider = $item.Provider; cidrs = $item.Cidrs.Count; rules = $ruleCount; token = $item.Token; health = $conn.Healthy }
    Clear-CBFlag "pending-$($item.Provider)"
}
Write-CBLog "Block committed for: $((($plan | ForEach-Object { $_.Provider }) -join ', '))." 'OK'

# 7) Optional trial window.
if ($TrialMinutes -gt 0) { Register-TrialRollback -Minutes $TrialMinutes }

exit 0
