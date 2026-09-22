#!/usr/bin/env bash
# Cloud Blocker (Linux) - shared library. Sourced by cloudblocker.sh. Bash 4+.

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${CLOUDBLOCKER_CONFIG:=/etc/cloudblocker/cloudblocker.conf}"
if [ -f "$CLOUDBLOCKER_CONFIG" ]; then
  # shellcheck source=/dev/null
  . "$CLOUDBLOCKER_CONFIG"
elif [ -f "$SELF_DIR/cloudblocker.conf" ]; then
  # shellcheck source=/dev/null
  . "$SELF_DIR/cloudblocker.conf"
fi

: "${CLOUDBLOCKER_DIR:=/etc/cloudblocker}"
: "${NFT_TABLE:=cloudblocker}"
: "${MAX_CIDRS_WITHOUT_FORCE:=5000}"
: "${COMMIT_GRACE_SECONDS:=300}"
: "${TRIAL_MINUTES_DEFAULT:=15}"
if [ "${#CANARIES[@]}" -eq 0 ]; then CANARIES=("1.1.1.1:443" "9.9.9.9:443" "8.8.8.8:53"); fi

STATE_DIR="$CLOUDBLOCKER_DIR/state"
LOG_DIR="$CLOUDBLOCKER_DIR/logs"
LOG_FILE="$LOG_DIR/cloudblocker.log"
NFT_FILE="$CLOUDBLOCKER_DIR/cloudblocker.nft"

_prog() {
  if [ -n "${SELF_DIR:-}" ] && [ -f "$SELF_DIR/cloudblocker-fetch.py" ]; then
    echo "$SELF_DIR/cloudblocker-fetch.py"
  else
    echo "$CLOUDBLOCKER_DIR/cloudblocker-fetch.py"
  fi
}

log() { # level message [provider]
  local level="$1" msg="$2" prov="${3:-}"
  local ts tag=""
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  [ -n "$prov" ] && tag="[$prov]"
  mkdir -p "$LOG_DIR"
  printf '[%s][%s]%s %s\n' "$ts" "$level" "$tag" "$msg" | tee -a "$LOG_FILE" >&2
}

ensure_dirs() { mkdir -p "$STATE_DIR" "$LOG_DIR"; }

require_root() {
  if [ "$(id -u)" -ne 0 ]; then log ERROR "must run as root (use sudo)"; exit 1; fi
}

have() { command -v "$1" >/dev/null 2>&1; }

tcp_ok() { timeout 3 bash -c ">/dev/tcp/$1/$2" >/dev/null 2>&1; }

canary() { # 0 = at least one canary reachable
  local up=0 total=0 ep host port
  for ep in "${CANARIES[@]}"; do
    host="${ep%:*}"; port="${ep##*:}"; total=$((total + 1))
    if tcp_ok "$host" "$port"; then up=$((up + 1)); fi
  done
  log INFO "canary: $up/$total reachable"
  [ "$up" -ge 1 ]
}

wait_network() { # seconds
  local deadline=$(( $(date +%s) + ${1:-180} ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if canary; then return 0; fi
    log WARN "network not ready, waiting..."
    sleep 5
  done
  log ERROR "network not ready after ${1:-180}s"
  return 1
}

providers_enabled() { echo "aws gcp azure"; }

blocked_providers() {
  local f
  for f in "$STATE_DIR"/*.set; do
    [ -s "$f" ] || continue
    basename "$f" .set
  done
}

sanitize() { # stdin -> stdout: valid, non-private IPv4 CIDRs, /8../32
  awk -F/ '
    NF==2 && $2 ~ /^[0-9]+$/ && $2+0 >= 8 && $2+0 <= 32 {
      n = split($1, o, ".");
      if (n == 4 && o[1] != "" && o[2] != "" && o[3] != "" && o[4] != "") {
        ok = 1;
        for (i = 1; i <= 4; i++) { if (o[i]+0 > 255) ok = 0 }
        if (o[1]+0 == 0 || o[1]+0 == 10 || o[1]+0 == 127 || o[1]+0 >= 224) ok = 0;
        if (o[1]+0 == 100 && o[2]+0 >= 64 && o[2]+0 <= 127) ok = 0;
        if (o[1]+0 == 169 && o[2]+0 == 254) ok = 0;
        if (o[1]+0 == 172 && o[2]+0 >= 16 && o[2]+0 <= 31) ok = 0;
        if (o[1]+0 == 192 && o[2]+0 == 168) ok = 0;
        if (o[1]+0 == 192 && o[2]+0 == 0) ok = 0;
        if (o[1]+0 == 198 && (o[2]+0 == 18 || o[2]+0 == 19)) ok = 0;
        if (o[1]+0 == 203 && o[2]+0 == 0 && o[3]+0 == 113) ok = 0;
        if (ok) print $0;
      }
    }'
}

fetch_cidrs() { # provider -> raw CIDRs on stdout
  python3 "$(_prog)" "$1"
}

nft_apply() { # rebuild the whole nftables table from state files (atomic)
  require_root
  local provs p tmp
  provs="$(blocked_providers)"
  tmp="$(mktemp)"
  {
    echo "table inet $NFT_TABLE {"
    if [ -n "$provs" ]; then
      for p in $provs; do
        echo "  set bl_$p {"
        echo "    type ipv4_addr;"
        echo "    flags interval;"
        echo "    elements = {"
        sed 's/$/,/' "$STATE_DIR/$p.set" | sed '$ s/,$//'
        echo "    }"
        echo "  }"
      done
      echo "  chain input {"
      echo "    type filter hook input priority 0; policy accept;"
      for p in $provs; do echo "    ip daddr @bl_$p drop"; done
      echo "  }"
      echo "  chain output {"
      echo "    type filter hook output priority 0; policy accept;"
      for p in $provs; do echo "    ip daddr @bl_$p drop"; done
      echo "  }"
    fi
    echo "}"
  } > "$tmp"

  nft delete table inet "$NFT_TABLE" 2>/dev/null || true
  if [ -n "$provs" ]; then
    if ! nft -f "$tmp"; then
      log ERROR "nft apply failed"
      rm -f "$tmp"
      return 1
    fi
  fi
  cp -f "$tmp" "$NFT_FILE" 2>/dev/null || true
  rm -f "$tmp"
}

unblock_all() {
  rm -f "$STATE_DIR"/*.set
  nft_apply
}

schedule_trial() { # minutes
  local m="$1"
  if have systemd-run; then
    systemd-run --on-active="${m}m" --unit=cloudblocker-trial-unblock --collect \
      "$(command -v cloudblocker || echo /usr/local/bin/cloudblocker)" unblock all \
      && log WARN "trial armed: auto-unblock in ${m} min"
  elif have at; then
    echo "$(command -v cloudblocker || echo /usr/local/bin/cloudblocker) unblock all" | at now + "${m}" minutes \
      && log WARN "trial armed (at): auto-unblock in ${m} min"
  else
    log WARN "cannot arm trial (no systemd-run/at available)"
  fi
}
