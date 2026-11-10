#!/usr/bin/env bash
# Runs ON an Azure VM (copied there by deploy.sh). Installs the Python environment and the
# project code. Usage: bash vm_setup.sh server|clients
set -euo pipefail
ROLE=${1:?server|clients}
BASE=$HOME/fids
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv python3-pip >/dev/null
if [ "$ROLE" = server ]; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io >/dev/null
  sudo usermod -aG docker "$USER"
fi
mkdir -p "$BASE/code" "$BASE/runs" "$BASE/flwr_home"
tar -xzf "$BASE/code.tgz" -C "$BASE/code"
[ -d "$BASE/venv" ] || python3 -m venv "$BASE/venv"
"$BASE/venv/bin/pip" install -q --upgrade pip
"$BASE/venv/bin/pip" install -q --index-url https://download.pytorch.org/whl/cpu torch==2.14.1
"$BASE/venv/bin/pip" install -q flwr==1.42.0 numpy==2.5.3 scikit-learn==1.9.1 pyyaml psutil
"$BASE/venv/bin/pip" install -q --no-deps -e "$BASE/code"
"$BASE/venv/bin/python" -c "import torch, flwr, federated_ids; print('ok', torch.__version__, flwr.__version__)"
# nightly safety net: deallocate this VM at 18:00 UTC = 23:30 IST (VM clock is UTC)
chmod +x "$BASE/self_deallocate.sh"
( { crontab -l 2>/dev/null || true; } | { grep -v self_deallocate || true; }; echo "0 18 * * * $BASE/self_deallocate.sh >> $BASE/self_deallocate.log 2>&1" ) | crontab -
crontab -l | grep self_deallocate
