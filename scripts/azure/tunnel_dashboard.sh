#!/usr/bin/env bash
# Open the Azure-hosted dashboard in the laptop's browser through an SSH tunnel (Ctrl+C to close).
#   SERVER_IP=<ip> bash scripts/azure/tunnel_dashboard.sh     # then open http://127.0.0.1:18000
# Optionally also forwards the secured endpoint (fids-server 127.0.0.1:8443 -> https://127.0.0.1:18443).
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/azure/common.sh
PORT=${PORT:-18000}
echo "dashboard on Azure: http://127.0.0.1:$PORT   endpoint: https://127.0.0.1:18443   (Ctrl+C to close)"
# -N = no remote shell, just forward the ports while this runs
ssh -p "$SSH_PORT" "${SSH_OPTS[@]}" -N -L "$PORT:127.0.0.1:8000" -L "18443:127.0.0.1:8443" "$ADMIN@$SERVER_IP"
