#!/usr/bin/env bash
# Deploy the demo dashboard (demo/app.py) to fids-server and run it as a systemd service bound to
# 127.0.0.1:8000 there. Like the endpoint it is NOT exposed publicly (the NSG stays tcp/443 SSH only);
# open it through an SSH tunnel with scripts/azure/tunnel_dashboard.sh.
#
#   SERVER_IP=<ip> bash scripts/azure/serve_dashboard.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/azure/common.sh
LABEL=${LABEL:-"Azure VM fids-server"}
STAGE="$KEYDIR/stage"
mkdir -p "$STAGE"
# Only the dashboard, the project code it imports and the committed result tables; no raw data.
tar --force-local -czf "$STAGE/dashboard.tgz" --exclude='__pycache__' --exclude='*.egg-info' \
  src demo/app.py demo/bundle demo/static reports/tables
scp_any "$STAGE/dashboard.tgz" "$ADMIN@$SERVER_IP:fids/dashboard.tgz"
# unpack, install the web packages and register a systemd service so the dashboard restarts with the VM
on_server "set -e; rm -rf ~/fids/dashboard && mkdir -p ~/fids/dashboard && tar -xzf ~/fids/dashboard.tgz -C ~/fids/dashboard && \
  ~/fids/venv/bin/pip install -q fastapi uvicorn pydantic && \
  printf '%s\n' '[Unit]' 'Description=Federated IDS demo dashboard' 'After=network.target' '' \
    '[Service]' 'User=$ADMIN' 'WorkingDirectory=/home/$ADMIN/fids/dashboard' \
    'Environment=\"FIDS_DEPLOY=$LABEL\"' \
    'ExecStart=/home/$ADMIN/fids/venv/bin/python -m uvicorn demo.app:app --host 127.0.0.1 --port 8000' \
    'Restart=on-failure' '' '[Install]' 'WantedBy=multi-user.target' | sudo tee /etc/systemd/system/fids-dashboard.service >/dev/null && \
  sudo systemctl daemon-reload && sudo systemctl enable -q fids-dashboard && sudo systemctl restart fids-dashboard && \
  # wait until the dashboard answers (up to a minute)
  for i in \$(seq 1 30); do curl -sf http://127.0.0.1:8000/api/host && break; sleep 2; done; echo; \
  systemctl is-active fids-dashboard"
echo "[dashboard] running on fids-server 127.0.0.1:8000 (open it with scripts/azure/tunnel_dashboard.sh)"
