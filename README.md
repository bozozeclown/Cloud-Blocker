# Cloud Blocker

Block a cloud provider's published IPv4 ranges (AWS / GCP / Azure) at the firewall,
on **Windows** and **Linux**. Built to be *safe*: a block that would cut the machine
off the internet is detected by a connectivity canary and reverted automatically, and
a guard watchdog undoes interrupted applies.

> The original one-shot approach (delete rules → blindly recreate them) could "brick"
> the PC: blocking all of AWS/Azure/GCP takes out huge parts of the web (CDNs, DNS,
> launcher backends), and there was no health check or rollback. This version fixes
> that on both platforms.

## Shared safety model

1. **Preflight** – wait for a working network, then fetch + sanitise *all* requested
   providers **before** touching the firewall. A failed download changes nothing.
2. **Sanitise** – keep valid IPv4 CIDRs `/8`..`/32`; drop private / loopback /
   link-local / multicast / special-use ranges; dedupe.
3. **Size guard** – refuse a block larger than `MAX_CIDRS_WITHOUT_FORCE` (default
   5000) unless forced. (Azure alone is ~45k CIDRs.)
4. **Atomic apply** – all rules live in one managed group/table, so unblock is a
   single reliable operation.
5. **Canary + rollback** – TCP-test `1.1.1.1:443`, `9.9.9.9:443`, `8.8.8.8:53`
   (none inside AWS/Azure/GCP ranges). If all fail after applying, the block is
   rolled back automatically.
6. **Guard** – `pending`/`committed` flags let a watchdog revert an apply that was
   interrupted (engine killed mid-run) or that left the box offline.

The canary only proves the machine isn't fully cut off. Blocking a whole hyperscaler
is inherently disruptive for services *hosted* on it — use a **trial block** for
anything you're unsure about.

---

## Windows

Native PowerShell engine + a compiled tray app.

### Files

| File | Purpose |
|---|---|
| `CloudBlocker.Common.psm1` | Shared helpers (fetch/parse, CIDR safety, firewall group, canary, flags) |
| `Block-CloudIPs.ps1` | Engine: `-Action Block|Unblock|Verify|Guard` |
| `Manage-CloudBlocker.ps1` | Interactive manager + scriptable commands |
| `cloudblocker.config.json` | Canaries, thresholds, providers |
| `CloudBlockerTray.exe` | Tray-icon front-end (starts at logon) |
| `CloudBlockerTray.cs`, `app.manifest`, `Build-CloudBlockerTray.ps1` | Tray source + build |
| `cb.ico` | Icon asset |

### Usage (elevated)

```powershell
powershell -ExecutionPolicy Bypass -File .\Manage-CloudBlocker.ps1
powershell -ExecutionPolicy Bypass -File .\Manage-CloudBlocker.ps1 -Command Status
powershell -ExecutionPolicy Bypass -File .\Block-CloudIPs.ps1 -Provider GCP -Action Block -TrialMinutes 15
powershell -ExecutionPolicy Bypass -File .\Block-CloudIPs.ps1 -Provider ALL -Action Unblock
```

Tray app: right-click the icon for Status, Block, Trial block, Unblock (incl. PANIC),
open manager/folder/log, and a **Run at startup** toggle. It requests admin rights and
is registered to start at logon via the `Cloud Blocker Tray` scheduled task.

Rebuild the tray exe:

```powershell
powershell -ExecutionPolicy Bypass -File .\Build-CloudBlockerTray.ps1
```

### Requirements

Windows 10/11 with Windows PowerShell 5.1 and .NET Framework 4.x (present by default).
Defender exclusions for the AutoClaw install are unrelated to this tool.

---

## Linux (Ubuntu / Debian)

nftables-based engine with the same safety model, installed as a `cloudblocker`
command plus systemd units.

### Install

```bash
sudo ./linux/install.sh
```

Installs scripts to `/usr/local/lib/cloudblocker/`, config to
`/etc/cloudblocker/cloudblocker.conf`, a `cloudblocker` command, and systemd units
(guard timer enabled; daily block timer left disabled).

### Usage

```bash
sudo cloudblocker block   gcp --trial 15
sudo cloudblocker block   aws
sudo cloudblocker block   all --force
sudo cloudblocker unblock all
sudo cloudblocker status
sudo cloudblocker guard
```

### Files

| File | Purpose |
|---|---|
| `linux/cloudblocker.sh` | Engine: block / unblock / verify / guard |
| `linux/cloudblocker-common.sh` | Shared library (canary, sanitise, nftables, flags) |
| `linux/cloudblocker-fetch.py` | Fetches + parses provider ranges (stdlib only) |
| `linux/cloudblocker.conf` | Canaries, thresholds, provider URLs |
| `linux/install.sh` | Ubuntu/Debian installer |
| `linux/systemd/*` | Guard + daily-refresh units |

See `linux/README.md` for details, uninstall, and how the nftables table is built.

---

## Notes

- **Alibaba is not supported/disabled**: Alibaba Cloud publishes no stable
  machine-readable IP-range JSON, so there is no reliable source URL to parse.
- Provider endpoints: AWS `ip-ranges.amazonaws.com/ip-ranges.json`, GCP
  `gstatic.com/ipranges/cloud.json`, Azure Service Tags (auto-resolved).
- Only IPv4 CIDRs are blocked.
