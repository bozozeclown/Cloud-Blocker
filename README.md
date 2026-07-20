## Cloud Blocker & Network Recon Toolkit

<img src="Cloud-Block.png" alt="Cloud-Block-Cope" width="500" />

A raw, dependency-light PowerShell toolkit for enforcing strict cloud IP firewalls on Windows, hunting unauthorized connections, and integrating deep network reconnaissance via Nmap. 

## Features

- **Multi-Cloud Firewall Blocking**: Ingests live JSON CIDR lists from AWS, GCP, and Azure, batching them into high-performance Windows Firewall rules.
- **Automated Scheduled Tasks**: Installs persistent daily tasks to keep blocklists updated automatically.
- **Native Nmap Integration**: Wraps `nmap.exe` into a PowerShell object API (`Nmap-Helper.ps1`). Captures XML output natively—no regex parsing of raw terminal text.
- **Pure PS Fallback Scanner**: If Nmap isn't installed, recon scripts automatically fall back to a native .NET TCP connect scanner.
- **Proxy Enumeration & Routing**: Scan targets *through* HTTP/SOCKS proxies, or scan a target *to see if it is* an open proxy.
- **Real-Time Wiretap with Auto-Enrichment**: Monitor active TCP connections and automatically Nmap new remote IPs, dumping service/version data sequentially to a CSV.
- **Firewall Verification**: Uses Nmap to actively prove that installed firewall rules are dropping packets (checking for `filtered` states), not just silently failing.

## Prerequisites

1. **Administrator Rights**: Required for Windows Firewall changes, scheduled tasks, and Nmap SYN/OS scans.
2. **Nmap (Optional but Highly Recommended)**: Download from [nmap.org](https://nmap.org/). The scripts will automatically find it in your `PATH` or default `Program Files` directories. If missing, scripts fall back to basic PS port scanning.
3. **PowerShell 5.1+** (Run via `powershell.exe`, not `pwsh`).

---

## Script Reference & Usage

### Core Firewall Management

#### `Manage-CloudBlocker.ps1`
The raw CLI entry point for managing your cloud blocklists. Prints ASCII art, gives you a prompt, and executes commands sequentially without wiping your terminal history.

```powershell
.\Manage-CloudBlocker.ps1
```
**Commands:**
- `1`: Install & Update ALL providers
- `2`: Install & Update specific provider
- `3`: Unblock specific provider
- `4`: Unblock ALL (Nuke)
- `5`: Verify blocks with nmap
- `6`: Exit

#### `Block-CloudIPs.ps1`
The underlying engine. Usually called by the manager, but can be run directly. Fetches IPs, sanitizes them, batches them into firewall rules, and saves state.

```powershell
.\Block-CloudIPs.ps1 -Provider AWS -Action Block
.\Block-CloudIPs.ps1 -Provider GCP -Action Unblock
```

#### `Verify-CloudBlocks.ps1`
Proves the firewall rules are actually working. Samples IPs from the installed blocklists and runs an Nmap scan against them. If ports show as `filtered`, the block is working. If ports show as `open` or `closed`, your block is leaking.

```powershell
.\Verify-CloudBlocks.ps1 -Provider AWS -SampleSize 3
```

---

### Network Reconnaissance & Nmap Integration

#### `Nmap-Helper.ps1`
The core API. Dot-sourced by other scripts. Handles Nmap execution, XML parsing, proxy routing, and the pure PowerShell fallback scanner. You don't run this directly, but you can use its functions in your own scripts:
```powershell
. .\Nmap-Helper.ps1
Invoke-Nmap -Targets "10.10.10.5" -ServiceScan -TopPorts 100 -Proxies "http://1.2.3.4:8080"
```

#### `Network-Wiretap.ps1`
Monitors active TCP connections. When a new remote IP connects, it automatically runs a scan (Nmap or PS fallback) once per IP and logs the open ports to a CSV.

```powershell
.\Network-Wiretap.ps1 -AutoEnrich
```
**Outputs:**
- `NetworkWiretap.csv`: Raw connection logs (Process, PID, IP, Port).
- `NetworkWiretap-Enriched.csv`: Scan results (RemoteIP, OS, Port, Service, Product, Version).
- `NetworkWiretap-ScanState.xml`: Tracks scan cooldowns so IPs aren't scanned repeatedly.

#### `Scan-Target.ps1`
Standalone CLI scanner for ad-hoc target analysis. 

**Basic Scan:**
```powershell
.\Scan-Target.ps1 -Target 23.46.189.219 -TopPorts 200 -OsDetect -ConnectScan
```

**Check if target is an open proxy:**
Uses Nmap NSE scripts (`http-open-proxy`, `socks-open-proxy`) against common proxy ports.
```powershell
.\Scan-Target.ps1 -Target 192.168.1.50 -CheckProxies
```

**Scan a target THROUGH a proxy chain:**
Routes the Nmap scan through HTTP/SOCKS proxies.
```powershell
.\Scan-Target.ps1 -Target 10.10.10.5 -TopPorts 50 -Proxies "http://1.2.3.4:8080","socks4://5.6.7.8:1080"
```

#### `Hunt-IPAdess.ps1`
Sits in a loop waiting for a connection to a specific IP. When detected, it triggers a one-shot Nmap enrichment scan.

```powershell
.\Hunt-IPAdess.ps1 -TargetIP 172.217.22.174 -EnrichWithNmap
```

---

### Utilities

#### `Kill-MSTelemetry.ps1`
Severs Windows telemetry. Blocks the Vortex IP in the firewall, disables the `DiagTrack` service, sets OS telemetry to 'Security Only' via registry, and null-routes telemetry DNS domains in the hosts file.

```powershell
.\Kill-MSTelemetry.ps1
```

#### `Chunk-PS1Files.ps1`
Developer utility. Concatenates all `.ps1` files in a directory and splits them into AI-digestible `.txt` chunks (useful for feeding large codebases into LLMs).

```powershell
.\Chunk-PS1Files.ps1
```

---

## File Structure

Keep all scripts in the same directory. The scripts use `$PSScriptRoot` to locate each other.

```text
F:\Work\Software\Cloud Blocker\
├── Manage-CloudBlocker.ps1   # Main CLI entry point
├── Block-CloudIPs.ps1        # Firewall engine
├── Verify-CloudBlocks.ps1    # Nmap block verification
├── Nmap-Helper.ps1           # Shared Nmap/PS scan API
├── Network-Wiretap.ps1       # Auto-enriching TCP monitor
├── Scan-Target.ps1           # Proxy-capable ad-hoc scanner
├── Hunt-IPAdess.ps1          # Targeted IP hunter
├── Kill-MSTelemetry.ps1      # OS telemetry killer
└── Chunk-PS1Files.ps1        # Dev utility
```
