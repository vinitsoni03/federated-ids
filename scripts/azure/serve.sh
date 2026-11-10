#!/usr/bin/env bash
# Package a trained run as a model bundle, build the endpoint image ON the server VM and run it
# bound to 127.0.0.1:8443 there (reachable only through an SSH tunnel). The API key is generated
# locally once and kept outside the repository ($KEYDIR/api_key).
#
#   RUN_NAME=flower_azure_hybrid_category_iid_s0 bash scripts/azure/serve.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/azure/common.sh
RUN_NAME=${RUN_NAME:-flower_azure_hybrid_category_iid_s0}
PY=${PY:-.venv/Scripts/python.exe}
BUNDLE="$KEYDIR/stage/model_bundle"
rm -rf "$BUNDLE"
"$PY" scripts/package_model.py --run "artifacts/runs/$RUN_NAME" --data-dir "$DATA" --out "$BUNDLE"
[ -f "$KEYDIR/api_key" ] || "$PY" -c "import secrets; print(secrets.token_urlsafe(32))" > "$KEYDIR/api_key"

on_server "rm -rf ~/fids/model && mkdir -p ~/fids/model ~/fids/build"
scp_any "$BUNDLE"/* "$ADMIN@$SERVER_IP:fids/model/"
scp_any "$KEYDIR/api_key" "$ADMIN@$SERVER_IP:fids/api_key"
on_server "chmod 600 ~/fids/api_key ~/fids/tls/server.key; cd ~/fids/build && rm -rf ctx && mkdir ctx && \
  tar -xzf ~/fids/code.tgz -C ctx && cp ctx/serving/Dockerfile ctx/ && \
  sudo docker build -q -t fids-endpoint:1 ctx && \
  (sudo docker rm -f fids-endpoint >/dev/null 2>&1 || true) && \
  sudo docker run -d --name fids-endpoint --restart unless-stopped -p 127.0.0.1:8443:8443 \
    -e API_KEY=\"\$(cat ~/fids/api_key)\" -v ~/fids/model:/model:ro -v ~/fids/tls:/tls:ro fids-endpoint:1 && \
  sleep 5 && sudo docker logs --tail 5 fids-endpoint"
echo "[serve] endpoint running on fids-server 127.0.0.1:8443 (open a tunnel with scripts/azure/tunnel_endpoint.sh)"
