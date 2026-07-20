<#
.SYNOPSIS
    Interactive Menu for Managing Cloud IP Blockers.
#>

 $SCRIPT_DIR = $PSScriptRoot
 $ENGINE_PATH = Join-Path $SCRIPT_DIR "Block-CloudIPs.ps1"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host '[ERROR] Please run this script as Administrator.' -ForegroundColor Red
    exit 1
}

function Register-Task($Provider) {
    $TASK_NAME = "Cloud IP Blocklist - $Provider"
    Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ENGINE_PATH`" -Provider $Provider -Action Block"
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $trigBoot = New-ScheduledTaskTrigger -AtStartup; $trigBoot.Delay = 'PT120S'
    $runTime = switch ($Provider) { 'AWS' { '04:20' }; 'GCP' { '04:21' }; 'Azure' { '04:22' } }
    $trigDaily = New-ScheduledTaskTrigger -Daily -At $runTime
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
    Register-ScheduledTask -TaskName $TASK_NAME -Action $action -Trigger @($trigBoot, $trigDaily) -Principal $principal -Settings $settings -Force | Out-Null
}

function Show-Menu {
    Clear-Host
    Write-Host "=================================" -ForegroundColor Cyan
    Write-Host "   Cloud IP Blocker Manager      " -ForegroundColor Cyan
    Write-Host "=================================" -ForegroundColor Cyan
    Write-Host "1. Install & Update ALL"
    Write-Host "2. Install & Update specific provider"
    Write-Host "3. Unblock specific provider"
    Write-Host "4. Unblock ALL (Nuke)"
    Write-Host "5. Exit"
    Write-Host "=================================" -ForegroundColor Cyan
}

while ($true) {
    Show-Menu
    $choice = Read-Host "Select an option [1-5]"

    switch ($choice) {
        '1' {
            Write-Host "`n[*] Installing and updating all providers..." -ForegroundColor Yellow
            $providers = @('AWS', 'GCP', 'Azure')
            foreach ($p in $providers) {
                Write-Host "`n--- Setting up $p ---" -ForegroundColor Cyan
                Register-Task -Provider $p
                Start-ScheduledTask -TaskName "Cloud IP Blocklist - $p"
                Start-Sleep -Seconds 2
            }
            Write-Host "`n[OK] All tasks triggered. Check logs in 1-2 minutes." -ForegroundColor Green
            Read-Host "Press Enter to continue"
        }
        '2' {
            $p = Read-Host "Enter provider (AWS, GCP, Azure)"
            if ($p -in @('AWS', 'GCP', 'Azure')) {
                Write-Host "`n[*] Setting up $p..." -ForegroundColor Yellow
                Register-Task -Provider $p
                Start-ScheduledTask -TaskName "Cloud IP Blocklist - $p"
                Write-Host "[OK] Task triggered for $p." -ForegroundColor Green
            } else { Write-Host "[ERROR] Invalid provider." -ForegroundColor Red }
            Read-Host "Press Enter to continue"
        }
        '3' {
            $p = Read-Host "Enter provider to unblock (AWS, GCP, Azure)"
            if ($p -in @('AWS', 'GCP', 'Azure')) {
                Write-Host "`n[*] Unblocking $p..." -ForegroundColor Yellow
                & powershell -ExecutionPolicy Bypass -File $ENGINE_PATH -Provider $p -Action Unblock
            } else { Write-Host "[ERROR] Invalid provider." -ForegroundColor Red }
            Read-Host "Press Enter to continue"
        }
        '4' {
            Write-Host "`n[*] Nuking all cloud blockers..." -ForegroundColor Yellow
            $providers = @('AWS', 'GCP', 'Azure')
            foreach ($p in $providers) {
                & powershell -ExecutionPolicy Bypass -File $ENGINE_PATH -Provider $p -Action Unblock
            }
            Write-Host "[OK] All providers unblocked." -ForegroundColor Green
            Read-Host "Press Enter to continue"
        }
        '5' {
            exit 0
        }
        default {
            Write-Host "Invalid choice. Try again." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}