#!/usr/bin/env bash
# Open an SSH tunnel to the endpoint and run a test request with real test windows.
#   bash scripts/azure/tunnel_endpoint.sh          # tunnel + smoke test, then closes the tunnel
#   KEEP=1 bash scripts/azure/tunnel_endpoint.sh   # keep the tunnel open for a demo (Ctrl+C to close)
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/azure/common.sh
PORT=${PORT:-18443}
PY=${PY:-.venv/Scripts/python.exe}
ssh -p "$SSH_PORT" "${SSH_OPTS[@]}" -N -L "$PORT:127.0.0.1:8443" "$ADMIN@$SERVER_IP" & TP=$!
trap 'kill $TP 2>/dev/null' EXIT
sleep 4
"$PY" scripts/azure/endpoint_smoke.py --url "https://127.0.0.1:$PORT" --ca "$TLS/ca.crt" --api-key-file "$KEYDIR/api_key"
if [ "${KEEP:-0}" = 1 ]; then echo "tunnel open on https://127.0.0.1:$PORT (Ctrl+C to close)"; wait $TP; fi
