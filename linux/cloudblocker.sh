#!/usr/bin/env bash
# Cloud Blocker (Linux) - engine.
# Usage: cloudblocker <block|unblock|verify|guard|status> [aws|gcp|azure|all] [options]
#
# Safety model (mirrors the Windows build):
#   * waits for a working network before touching the firewall
#   * fetches + sanitises ALL targets before changing anything
#   * single nftables table => atomic, reliable unblock
#   * connectivity canary + automatic rollback if a block cuts you off
#   * pending/committed flags + guard timer revert interrupted applies
#   * refuses oversized blocks without --force; --trial auto-unblocks

set -u
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$SELF_DIR/cloudblocker-common.sh"

usage() {
  cat <<'EOF'
cloudblocker <command> [provider] [options]

Commands:
  block   <aws|gcp|azure|all> [--force] [--trial MINUTES]
  unblock <aws|gcp|azure|all>
  verify
  guard
  status

Examples:
  sudo cloudblocker block gcp --trial 15
  sudo cloudblocker block all --force
  sudo cloudblocker unblock all
  sudo cloudblocker status
EOF
}

resolve_targets() { # provider -> space separated list
  local provider="$1"
  if [ "$provider" = "all" ]; then
    { providers_enabled; blocked_providers; } | sort -u | tr '\n' ' '
  else
    echo "$provider"
  fi
}

cmd_block() {
  local provider="${1:-}"; shift || true
  [ -n "$provider" ] || { usage; exit 2; }
  local force=0 trial=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --force) force=1 ;;
      --trial) trial="${2:-$TRIAL_MINUTES_DEFAULT}"; shift ;;
      --trial=*) trial="${1#*=}" ;;
      *) log WARN "ignoring unknown option: $1" ;;
    esac
    shift || true
  done

  ensure_dirs
  require_root
  local targets; targets="$(resolve_targets "$provider")"
  [ -n "$targets" ] || { log ERROR "no targets"; exit 1; }

  wait_network 180 || { log ERROR "aborting: no working network"; exit 1; }

  local plan=() total=0 p raw clean n
  for p in $targets; do
    log INFO "fetching $p ..." "$p"
    if ! raw="$(fetch_cidrs "$p" 2>/dev/null)"; then
      log ERROR "fetch failed for $p (leaving existing rules untouched)" "$p"
      continue
    fi
    clean="$(printf '%s\n' "$raw" | sanitize | sort -u | grep .)"
    n="$(printf '%s\n' "$clean" | grep -c . )"
    if [ "$n" -eq 0 ]; then log ERROR "no valid CIDRs for $p" "$p"; continue; fi
    log INFO "$p: $n valid IPv4 CIDRs" "$p"
    plan+=("$p")
    printf '%s\n' "$clean" > "$STATE_DIR/$p.pending"
    total=$((total + n))
  done

  if [ "${#plan[@]}" -eq 0 ]; then
    rm -f "$STATE_DIR"/*.pending
    log ERROR "nothing could be fetched; firewall untouched"
    exit 1
  fi

  if [ "$total" -gt "$MAX_CIDRS_WITHOUT_FORCE" ] && [ "$force" -ne 1 ]; then
    rm -f "$STATE_DIR"/*.pending
    log ERROR "refusing: $total CIDRs exceeds $MAX_CIDRS_WITHOUT_FORCE (re-run with --force)"
    exit 3
  fi

  for p in "${plan[@]}"; do
    touch "$STATE_DIR/pending-$p"
    mv -f "$STATE_DIR/$p.pending" "$STATE_DIR/$p.set"
  done

  nft_apply || { rm -f "$STATE_DIR"/pending-*; log ERROR "apply failed"; exit 1; }

  sleep 3
  if ! canary; then
    log CRITICAL "connectivity lost after apply - rolling back all cloud blocks"
    unblock_all
    rm -f "$STATE_DIR"/pending-*
    exit 2
  fi

  for p in "${plan[@]}"; do
    touch "$STATE_DIR/committed-$p"
    rm -f "$STATE_DIR/pending-$p"
    log OK "committed block: $p" "$p"
  done

  if [ "$trial" -gt 0 ]; then schedule_trial "$trial"; fi
  exit 0
}

cmd_unblock() {
  local provider="${1:-all}"
  ensure_dirs; require_root
  local p n
  if [ "$provider" = "all" ]; then
    n="$(blocked_providers | wc -l | tr -d ' ')"
    unblock_all
    rm -f "$STATE_DIR"/pending-* "$STATE_DIR"/committed-*
    log OK "unblocked all ($n provider set(s) removed)"
  else
    if [ -f "$STATE_DIR/$provider.set" ]; then
      rm -f "$STATE_DIR/$provider.set"
      nft_apply
      rm -f "$STATE_DIR/pending-$provider" "$STATE_DIR/committed-$provider"
      log OK "unblocked $provider"
    else
      log WARN "$provider was not blocked"
    fi
  fi
  exit 0
}

cmd_verify() {
  ensure_dirs
  local provs; provs="$(blocked_providers | tr '\n' ' ')"
  echo "Blocked providers : ${provs:-<none>}"
  local p c
  for p in $provs; do
    c="$(grep -c . "$STATE_DIR/$p.set" 2>/dev/null || echo 0)"
    echo "  $p: $c CIDRs"
  done
  if have nft; then
    echo "nftables table    : $(nft list table inet "$NFT_TABLE" >/dev/null 2>&1 && echo present || echo absent)"
  fi
  local pend; pend="$(ls "$STATE_DIR"/pending-* 2>/dev/null | tr '\n' ' ')"
  [ -n "$pend" ] && echo "Pending           : $pend"
  if canary; then echo "Connectivity      : HEALTHY"; else echo "Connectivity      : DOWN"; fi
  exit 0
}

cmd_guard() {
  ensure_dirs; require_root
  local pend; pend="$(ls "$STATE_DIR"/pending-* 2>/dev/null || true)"
  if [ -z "$pend" ]; then log INFO "guard: nothing pending"; exit 0; fi

  local total; total="$(blocked_providers | wc -l | tr -d ' ')"
  if ! canary && [ "$total" -gt 0 ]; then
    log CRITICAL "guard: pending apply AND connectivity down - rolling back all"
    unblock_all; rm -f "$STATE_DIR"/pending-*
    exit 2
  fi

  local now f age
  now=$(date +%s)
  for f in $pend; do
    age=$(( now - $(stat -c %Y "$f") ))
    if [ "$age" -gt "$COMMIT_GRACE_SECONDS" ]; then
      log CRITICAL "guard: stale pending '$(basename "$f")' (${age}s) - rolling back all"
      unblock_all; rm -f "$STATE_DIR"/pending-*
      exit 2
    fi
  done
  log INFO "guard: pending within grace window; leaving as-is"
  exit 0
}

main() {
  case "${1:-}" in
    block)   shift; cmd_block "$@" ;;
    unblock) shift; cmd_unblock "$@" ;;
    verify|status) cmd_verify ;;
    guard)   cmd_guard ;;
    ""|-h|--help|help) usage ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
