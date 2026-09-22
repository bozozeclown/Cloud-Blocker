<#
.SYNOPSIS
    Manager for the Cloud Blocker toolkit (v2).

.DESCRIPTION
    Interactive + scriptable control surface:
      * Install/uninstall the scheduled tasks (per-provider block + guard watchdog).
      * Block / unblock a provider or everything.
      * Trial-block with an automatic rollback window.
      * Status + connectivity health check.

.NOTES
    Run as Administrator.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('', 'Install', 'Uninstall', 'Status', 'Block', 'Unblock', 'Nuke', 'Trial')]
    [string]$Command = '',
    [ValidateSet('AWS', 'GCP', 'Azure', 'Alibaba', 'ALL')]
    [string]$Provider = 'ALL',
    [int]$TrialMinutes = 15
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'CloudBlocker.Common.psm1') -Force

$root       = $PSScriptRoot
$enginePath = Join-Path $root 'Block-CloudIPs.ps1'
$guardTask  = 'Cloud Blocker - Guard'
$taskPrefix = 'Cloud Blocklist - '

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Host '[ERROR] Run this script as Administrator.' -ForegroundColor Red; exit 1 }
}

function Invoke-Engine {
    param([string]$ProviderArg, [string]$ActionArg = 'Block', [switch]$Force, [int]$TrialMins = 0)
    $psArgs = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', "`"$enginePath`"", '-Provider', $ProviderArg, '-Action', $ActionArg)
    if ($Force) { $psArgs += '-Force' }
    if ($TrialMins -gt 0) { $psArgs += @('-TrialMinutes', "$TrialMins") }
    & powershell.exe @psArgs
    return $LASTEXITCODE
}

function Register-BlockTask {
    param([string]$P, [string]$RunTime)
    $taskName  = "$taskPrefix$P"
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$enginePath`" -Provider $P -Action Block"
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $trigBoot  = New-ScheduledTaskTrigger -AtStartup; $trigBoot.Delay = 'PT120S'
    $trigDaily = New-ScheduledTaskTrigger -Daily -At $RunTime
    $settings  = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -DontStopIfGoingOnBatteries -StartWhenAvailable `
                    -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($trigBoot, $trigDaily) -Principal $principal -Settings $settings -Force | Out-Null
    Write-CBLog "Registered task '$taskName' (boot+120s, daily $RunTime)." 'OK'
}

function Register-GuardTask {
    param([int]$IntervalMinutes)
    Unregister-ScheduledTask -TaskName $guardTask -Confirm:$false -ErrorAction SilentlyContinue
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$enginePath`" -Provider ALL -Action Guard"
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $trigger   = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(2)) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) -RepetitionDuration (New-TimeSpan -Days 3650)
    $settings  = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    Register-ScheduledTask -TaskName $guardTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-CBLog "Registered guard task '$guardTask' (every $IntervalMinutes min)." 'OK'
}

function Install-CloudBlocker {
    $config = Get-CBConfig
    $times = @{ AWS = '04:20'; GCP = '04:21'; Azure = '04:22'; Alibaba = '04:23' }
    foreach ($p in Get-CBEnabledProviders -Config $config) {
        Register-BlockTask -P $p -RunTime $times[$p]
    }
    $interval = 10
    if ($config.guardIntervalMinutes) { $interval = [int]$config.guardIntervalMinutes }
    Register-GuardTask -IntervalMinutes $interval
    Write-CBLog "Install complete. Tasks will block on boot + daily; guard runs every $interval min." 'OK'
}

function Uninstall-CloudBlocker {
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like "$taskPrefix*" -or $_.TaskName -eq $guardTask -or $_.TaskName -eq 'CloudBlocker - TrialRollback' } |
        ForEach-Object { Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue; Write-CBLog "Removed task '$($_.TaskName)'." 'WARN' }
    $removed = Remove-CBAllRules
    Get-ChildItem -LiteralPath (Join-Path $root 'state') -Filter '*.json' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Write-CBLog "Uninstall complete. Removed $removed firewall rule(s) and cleared state." 'OK'
}

function Show-Status {
    $config = Get-CBConfig
    $status = Get-CBStatus -Config $config
    Write-Host ''
    Write-Host ("Firewall group : {0}" -f $status.Group)
    Write-Host ("Rules          : {0}" -f $status.RuleCount)
    foreach ($k in $status.ByProvider.Keys) { Write-Host ("   {0,-8}: {1} rule(s)" -f $k, $status.ByProvider[$k]) }
    if ($status.Pending.Count) { Write-Host ("Pending        : {0}" -f ($status.Pending -join ', ')) -ForegroundColor Yellow }
    $c = $status.Connectivity
    Write-Host ("Connectivity   : {0} ({1})" -f $(if ($c.Healthy) { 'HEALTHY' } else { 'DOWN' }), $c.Detail) -ForegroundColor $(if ($c.Healthy) { 'Green' } else { 'Red' })
    Write-Host ("Gateway        : {0} ({1})" -f $c.Gateway, $(if ($c.GatewayUp) { 'up' } else { 'no reply' }))
    Write-Host "Tasks:"
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like "$taskPrefix*" -or $_.TaskName -eq $guardTask -or $_.TaskName -eq 'CloudBlocker - TrialRollback' } |
        Select-Object TaskName, State | Format-Table -AutoSize | Out-String | Write-Host
    Write-Host ''
}

function Show-Menu {
    Write-Host ''
    Write-Host '  CLOUD BLOCKER - MANAGER' -ForegroundColor Cyan
    Write-Host '  -----------------------' -ForegroundColor DarkGray
    Write-Host '  1  Install / refresh scheduled tasks'
    Write-Host '  2  Block a provider (with trial window)'
    Write-Host '  3  Unblock a provider'
    Write-Host '  4  Unblock ALL (panic / nuke)'
    Write-Host '  5  Status + health check'
    Write-Host '  6  Uninstall (remove tasks + all rules)'
    Write-Host '  7  Exit'
    Write-Host ''
}

Assert-Admin

if ($Command) {
    switch ($Command) {
        'Install'   { Install-CloudBlocker }
        'Uninstall' { Uninstall-CloudBlocker }
        'Status'    { Show-Status }
        'Block'     { [void](Invoke-Engine -ProviderArg $Provider -ActionArg 'Block') }
        'Unblock'   { [void](Invoke-Engine -ProviderArg $Provider -ActionArg 'Unblock') }
        'Trial'     { [void](Invoke-Engine -ProviderArg $Provider -ActionArg 'Block' -TrialMins $TrialMinutes) }
        'Nuke'      { [void](Invoke-Engine -ProviderArg 'ALL' -ActionArg 'Unblock') }
    }
    exit 0
}

while ($true) {
    Show-Menu
    $choice = Read-Host '[cloud-blocker]'
    switch ($choice) {
        '1' { Install-CloudBlocker }
        '2' {
            $p = Read-Host 'Provider (AWS/GCP/Azure/ALL)'
            if ($p -notin @('AWS', 'GCP', 'Azure', 'ALL')) { Write-Host '[ERROR] Invalid provider.' -ForegroundColor Red; break }
            $m = Read-Host "Trial window in minutes (auto-unblock; 0 = none) [15]"
            if (-not $m) { $m = 15 }
            [void](Invoke-Engine -ProviderArg $p -ActionArg 'Block' -TrialMins ([int]$m))
        }
        '3' {
            $p = Read-Host 'Provider to unblock (AWS/GCP/Azure/ALL)'
            if ($p -notin @('AWS', 'GCP', 'Azure', 'ALL')) { Write-Host '[ERROR] Invalid provider.' -ForegroundColor Red; break }
            [void](Invoke-Engine -ProviderArg $p -ActionArg 'Unblock')
        }
        '4' { [void](Invoke-Engine -ProviderArg 'ALL' -ActionArg 'Unblock') }
        '5' { Show-Status }
        '6' { Uninstall-CloudBlocker }
        '7' { Write-Host 'Bye.' -ForegroundColor Cyan; exit 0 }
        default { Write-Host 'Invalid choice.' -ForegroundColor Red }
    }
}
