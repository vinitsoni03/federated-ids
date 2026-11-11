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
# The container runs as uid 10001 and reads /tls/cert.pem + /tls/key.pem, so it gets its own copy of the
# server certificate owned by that uid (key stays 600); the Flower TLS folder ~/fids/tls is not touched.
on_server "chmod 600 ~/fids/api_key ~/fids/tls/server.key && \
  sudo rm -rf ~/fids/endpoint_tls && mkdir ~/fids/endpoint_tls && \
  cp ~/fids/tls/server.pem ~/fids/endpoint_tls/cert.pem && cp ~/fids/tls/server.key ~/fids/endpoint_tls/key.pem && \
  sudo chown -R 10001:10001 ~/fids/endpoint_tls && sudo chmod 700 ~/fids/endpoint_tls && \
  sudo chmod 600 ~/fids/endpoint_tls/key.pem && sudo chmod 644 ~/fids/endpoint_tls/cert.pem && \
  cd ~/fids/build && rm -rf ctx && mkdir ctx && \
  tar -xzf ~/fids/code.tgz -C ctx && cp ctx/serving/Dockerfile ctx/ && \
  sudo docker build -q -t fids-endpoint:1 ctx && \
  (sudo docker rm -f fids-endpoint >/dev/null 2>&1 || true) && \
  sudo docker run -d --name fids-endpoint --restart unless-stopped -p 127.0.0.1:8443:8443 \
    -e API_KEY=\"\$(tr -d '\\r\\n' < ~/fids/api_key)\" -v ~/fids/model:/model:ro -v ~/fids/endpoint_tls:/tls:ro fids-endpoint:1 && \
  sleep 8 && sudo docker ps --filter name=fids-endpoint --format '{{.Status}}' && sudo docker logs --tail 5 fids-endpoint"
echo "[serve] endpoint running on fids-server 127.0.0.1:8443 (open a tunnel with scripts/azure/tunnel_endpoint.sh)"
