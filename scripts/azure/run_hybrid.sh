#!/usr/bin/env bash
# Hybrid federated run: SuperLink on the Azure server VM, SuperNodes on the Azure client VM
# (private network) and on this laptop (through an SSH tunnel), TLS with the private CA.
#
#   RUN_NAME=flower_azure_hybrid_category_iid_s0 ROUNDS=30 bash scripts/azure/run_hybrid.sh
#
# Results are copied back to artifacts/runs/$RUN_NAME/. All started processes and the tunnel are
# stopped at the end (also on error). VMs are NOT deallocated here: run scripts/azure/stop.sh.
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/azure/common.sh
RUN_NAME=${RUN_NAME:-flower_azure_hybrid_category_iid_s0}
ROUNDS=${ROUNDS:-30}
LOCAL_PORT=${LOCAL_PORT:-18000}
PY=${PY:-.venv/Scripts/python.exe}               # laptop environment with flwr installed
SCRIPTS=$(dirname "$PY")
OUT=artifacts/runs/$RUN_NAME
mkdir -p "$OUT/flower_logs"
REMOTE_ENV='export PATH=$HOME/fids/venv/bin:$PATH FLWR_HOME=$HOME/fids/flwr_home PYTHONIOENCODING=utf-8'
pids=()
cleanup() {
  set +e
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
  on_clients "pkill -f flower-supernode; pkill -f flwr-clientapp; pkill -f flower-superexec" 2>/dev/null
  on_server  "pkill -f flower-superlink; pkill -f flwr-serverapp; pkill -f flower-superexec" 2>/dev/null
  echo "[hybrid] stopped all Flower processes and the tunnel"
}
trap cleanup EXIT

echo "[hybrid] starting SuperLink on fids-server"
on_server "$REMOTE_ENV; cd ~/fids; nohup flower-superlink --ssl-ca-certfile tls/ca.crt --ssl-certfile tls/server.pem \
  --ssl-keyfile tls/server.key --host 0.0.0.0 --port 8000 --disable-runtime-dependency-installation \
  > runs/superlink_$RUN_NAME.log 2>&1 &"
sleep 8

echo "[hybrid] starting Azure SuperNodes ($AZURE_CLIENTS) on fids-clients"
port=9094
for i in $AZURE_CLIENTS; do
  on_clients "$REMOTE_ENV; cd ~/fids; nohup flower-supernode --root-certificates tls/ca.crt --superlink $SERVER_PRIV:8000 \
    --host 127.0.0.1 --port $port --node-config \"partition-id=$i num-partitions=$N_CLIENTS data-dir='/home/$ADMIN/fids/data'\" \
    > supernode_$i.log 2>&1 &"
  port=$((port + 1))
done

echo "[hybrid] opening SSH tunnel localhost:$LOCAL_PORT -> $SERVER_PRIV:8000"
ssh -p "$SSH_PORT" "${SSH_OPTS[@]}" -N -L "$LOCAL_PORT:127.0.0.1:8000" "$ADMIN@$SERVER_IP" & pids+=($!)
sleep 5

export FLWR_HOME="$KEYDIR/flwr_home_laptop" PYTHONIOENCODING=utf-8 PYTHONUTF8=1
# Application Control blocks the Flower launcher .exe files on the laptop, so every laptop-side Flower
# command runs as `python -c <entry point>`; win_shim/sitecustomize.py does the same for the commands
# Flower itself starts (flower-superexec, flwr-clientapp).
export PATH="$(cd "$SCRIPTS" && pwd):$PATH" PYTHONPATH="$(pwd -W)/flower_app;$(pwd -W)/scripts/azure/win_shim"
flwr_entry() {  # flwr_entry <command name> <module> <function> [args...]
  local name=$1 mod=$2 fn=$3; shift 3
  "$PY" -c "import sys; sys.argv[0] = '$name'; from $mod import $fn; $fn()" "$@"
}
mkdir -p "$FLWR_HOME"
printf '[superlink.azure]\naddress = "127.0.0.1:%s"\nroot-certificates = "%s"\n' "$LOCAL_PORT" "$TLS/ca.crt" > "$FLWR_HOME/config.toml"
echo "[hybrid] starting laptop SuperNodes ($LAPTOP_CLIENTS)"
port=9104
for i in $LAPTOP_CLIENTS; do
  # inline (not flwr_entry) so that $! is the Python process itself and cleanup() can stop it
  "$PY" -c "import sys; sys.argv[0] = 'flower-supernode'; from flwr.supernode.cli import flower_supernode; flower_supernode()" \
    --root-certificates "$TLS/ca.crt" --superlink "127.0.0.1:$LOCAL_PORT" \
    --host 127.0.0.1 --port $port --node-config "partition-id=$i num-partitions=$N_CLIENTS data-dir='$DATA'" \
    > "$OUT/flower_logs/laptop_supernode_$i.log" 2>&1 & pids+=($!)
  port=$((port + 1))
done
sleep 10

echo "[hybrid] flwr run ($ROUNDS rounds, $N_CLIENTS clients)"
t0=$(date +%s)
flwr_entry flwr flwr.cli.app app run flower_app azure --stream --run-config \
  "server-data-dir='/home/$ADMIN/fids/data' out-dir='/home/$ADMIN/fids/runs' run-name='$RUN_NAME' n-clients=$N_CLIENTS num-server-rounds=$ROUNDS device='cpu'" \
  > "$OUT/flower_logs/flwr_run.log" 2>&1
echo "[hybrid] flwr run finished in $(( $(date +%s) - t0 ))s"

scp_any -r "$ADMIN@$SERVER_IP:fids/runs/$RUN_NAME/*" "$OUT/"
scp_any "$ADMIN@$SERVER_IP:fids/runs/superlink_$RUN_NAME.log" "$OUT/flower_logs/" || true
for i in $AZURE_CLIENTS; do scp_any "$ADMIN@$CLIENTS_IP:fids/supernode_$i.log" "$OUT/flower_logs/azure_supernode_$i.log" || true; done
ls "$OUT"
