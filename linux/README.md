# Cloud Blocker (Linux / Ubuntu)

A faithful Linux port of the Windows Cloud Blocker. Blocks a cloud provider's
published IPv4 ranges with **nftables**, using the same reliability model:
connectivity canary + automatic rollback, a guard timer for interrupted applies,
atomic table rebuilds, and a size guard.

## Requirements

- Ubuntu 20.04+ (any Debian-based distro with `nftables` and `python3`)
- root / sudo (firewall changes)
- `nftables`, `python3` (installed automatically by `install.sh`)

## Install

```bash
sudo ./install.sh
```

This installs:
- scripts under `/usr/local/lib/cloudblocker/`
- a `cloudblocker` command in `/usr/local/bin/`
- config at `/etc/cloudblocker/cloudblocker.conf` (state/logs alongside)
- systemd units, with the **guard timer enabled** and the daily block timer **left disabled**

## Usage

```bash
sudo cloudblocker block   gcp --trial 15      # block GCP for 15 min, then auto-unblock
sudo cloudblocker block   aws                 # block AWS (refused if > 5000 CIDRs unless --force)
sudo cloudblocker block   all --force         # block AWS+GCP+Azure (huge!)
sudo cloudblocker unblock all                 # remove every cloud-block set
sudo cloudblocker unblock gcp
sudo cloudblocker status                      # what is blocked + live connectivity
sudo cloudblocker guard                       # manual guard run (also runs via timer)
```

## How it works (same safety model as Windows)

1. **Preflight** – waits for a working network, then fetches + sanitises *all*
   targets via `cloudblocker-fetch.py` (direct AWS/GCP endpoints, auto-resolved
   Azure URL). A failed fetch never touches the firewall.
2. **Sanitise** – keeps valid IPv4 CIDRs `/8`..`/32`, drops private / loopback /
   link-local / multicast / special-use ranges, dedupes.
3. **Size guard** – refuses a block larger than `MAX_CIDRS_WITHOUT_FORCE`
   (default 5000) unless `--force`.
4. **Apply** – writes `pending-<provider>` flags, then rebuilds the single
   `inet cloudblocker` nftables table (one set per provider, one drop rule per
   hook) in one atomic `nft -f`.
5. **Canary** – TCP-tests `1.1.1.1:443`, `9.9.9.9:443`, `8.8.8.8:53` (none inside
   AWS/Azure/GCP ranges). If all fail, the whole table is torn down.
6. **Commit** – on success the provider is marked committed.
7. **Guard timer** – every 10 min: if a `pending` apply exists and connectivity is
   down, or the flag is older than `COMMIT_GRACE_SECONDS` (engine died mid-apply),
   it removes the table.

The canary only proves the machine is not fully cut off. Blocking a whole
hyperscaler is inherently disruptive for services *hosted* on it — use `--trial`.

## Files

| File | Purpose |
|---|---|
| `cloudblocker.sh` | Engine: `block` / `unblock` / `verify` / `guard` |
| `cloudblocker-common.sh` | Shared library (canary, sanitise, nftables, flags) |
| `cloudblocker-fetch.py` | Fetches + parses provider ranges (stdlib only) |
| `cloudblocker.conf` | Canaries, thresholds, provider URLs |
| `install.sh` | Ubuntu/Debian installer |
| `systemd/*` | Guard + daily-refresh units |

## Uninstall

```bash
sudo systemctl disable --now cloudblocker-guard.timer cloudblocker.timer
sudo cloudblocker unblock all
sudo rm -rf /usr/local/lib/cloudblocker /etc/cloudblocker
sudo rm -f /usr/local/bin/cloudblocker
sudo rm -f /etc/systemd/system/cloudblocker*.service /etc/systemd/system/cloudblocker*.timer
sudo systemctl daemon-reload
```
