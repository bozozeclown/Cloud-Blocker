#!/usr/bin/env bash
# Cloud Blocker (Linux) installer for Ubuntu / Debian.
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="/usr/local/lib/cloudblocker"
BIN="/usr/local/bin/cloudblocker"
CONF_DIR="/etc/cloudblocker"

if [ "$(id -u)" -ne 0 ]; then echo "run as root (sudo ./install.sh)"; exit 1; fi

echo "[*] Installing dependencies (nftables, python3)..."
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq nftables python3 ca-certificates
else
  echo "    non-apt system: ensure nftables + python3 are installed"
fi

echo "[*] Installing files to $PREFIX ..."
install -d "$PREFIX" "$CONF_DIR" "$CONF_DIR/state" "$CONF_DIR/logs"
install -m 0644 "$SELF_DIR/cloudblocker-common.sh" "$PREFIX/cloudblocker-common.sh"
install -m 0755 "$SELF_DIR/cloudblocker-fetch.py"  "$PREFIX/cloudblocker-fetch.py"
install -m 0755 "$SELF_DIR/cloudblocker.sh"        "$PREFIX/cloudblocker.sh"

if [ ! -f "$CONF_DIR/cloudblocker.conf" ]; then
  install -m 0644 "$SELF_DIR/cloudblocker.conf" "$CONF_DIR/cloudblocker.conf"
  echo "    installed default config -> $CONF_DIR/cloudblocker.conf"
else
  echo "    kept existing config -> $CONF_DIR/cloudblocker.conf"
fi

ln -sf "$PREFIX/cloudblocker.sh" "$BIN"

if [ -d "$SELF_DIR/systemd" ] && command -v systemctl >/dev/null 2>&1; then
  echo "[*] Installing systemd units ..."
  install -m 0644 "$SELF_DIR/systemd/cloudblocker-guard.service" /etc/systemd/system/
  install -m 0644 "$SELF_DIR/systemd/cloudblocker-guard.timer"   /etc/systemd/system/
  install -m 0644 "$SELF_DIR/systemd/cloudblocker.service"       /etc/systemd/system/
  install -m 0644 "$SELF_DIR/systemd/cloudblocker.timer"         /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now cloudblocker-guard.timer
  echo "    guard timer enabled (every ~10 min); daily block timer left disabled"
fi

echo "[OK] Installed. Try:  sudo cloudblocker status"
