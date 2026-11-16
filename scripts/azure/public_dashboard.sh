#!/usr/bin/env bash
# Make the dashboard on fids-server reachable from the internet over plain http on port 80.
# Caddy listens on :80 and forwards to the dashboard (127.0.0.1:8000, set up by serve_dashboard.sh);
# the dashboard itself and the secured endpoint (8443) stay bound to localhost.
# Two portal steps go with this (not scriptable here, az CLI is not available):
#   * public IP fids-server-ip -> Configuration -> DNS name label (gives <label>.indiasouthcentral.cloudapp.azure.com)
#   * NSG fids-nsg -> inbound rule allowing TCP 80 from Any
#
#   SERVER_IP=<ip> bash scripts/azure/public_dashboard.sh
# Undo: delete the NSG rule (or run with UNDO=1 to also remove Caddy from the VM).
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/azure/common.sh
if [ "${UNDO:-0}" = 1 ]; then
  on_server "sudo systemctl disable --now caddy; sudo apt-get remove -y -qq caddy >/dev/null"
  echo "[public] Caddy removed; also delete the port-80 rule in fids-nsg"
  exit 0
fi
on_server "set -e
  # Caddy from Ubuntu's own repository (universe), no third-party source needed
  sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq caddy >/dev/null
  # forward everything on port 80 to the dashboard; no other site is served
  printf '%s\n' ':80 {' '  encode gzip' '  reverse_proxy 127.0.0.1:8000' '}' | sudo tee /etc/caddy/Caddyfile >/dev/null
  sudo systemctl enable -q caddy && sudo systemctl restart caddy
  sleep 2; curl -sf http://127.0.0.1/api/host; echo; systemctl is-active caddy"
echo "[public] Caddy forwards :80 -> dashboard; open port 80 in fids-nsg to make it public"
