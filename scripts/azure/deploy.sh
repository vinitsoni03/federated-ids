#!/usr/bin/env bash
# Copy code, the exported federated data and TLS material to the two VMs, then install.
# Only derived files go to Azure: per-client preprocessed partitions (client VM gets only its
# own clients' files), the server's validation/test set and the public CA certificate; the
# raw CICIoT2023 CSVs never leave this machine.
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/azure/common.sh
STAGE="$KEYDIR/stage"
rm -rf "$STAGE" && mkdir -p "$STAGE/server/data" "$STAGE/clients/data"
tar --force-local -czf "$STAGE/code.tgz" --exclude='__pycache__' --exclude='*.egg-info' pyproject.toml src flower_app serving
cp "$STAGE/code.tgz" "$STAGE/server/"; cp "$STAGE/code.tgz" "$STAGE/clients/"
cp "$DATA/server_eval.npz" "$DATA/manifest.json" "$DATA/preprocessor.json" "$STAGE/server/data/"
for i in $AZURE_CLIENTS; do cp "$DATA/client_$i.npz" "$STAGE/clients/data/"; done
cp "$DATA/manifest.json" "$STAGE/clients/data/"
cp "$TLS/ca.crt" "$TLS/server.pem" "$TLS/server.key" "$STAGE/server/"
cp "$TLS/ca.crt" "$STAGE/clients/"
for r in server clients; do cp scripts/azure/vm_setup.sh scripts/azure/self_deallocate.sh "$STAGE/$r/"; done

on_server "mkdir -p ~/fids/tls && chmod 700 ~/fids/tls"
scp_any -r "$STAGE/server/code.tgz" "$STAGE/server/vm_setup.sh" "$STAGE/server/self_deallocate.sh" "$STAGE/server/data" "$ADMIN@$SERVER_IP:fids/"
scp_any "$STAGE/server/ca.crt" "$STAGE/server/server.pem" "$STAGE/server/server.key" "$ADMIN@$SERVER_IP:fids/tls/"
on_server "chmod 600 ~/fids/tls/server.key"
on_clients "mkdir -p ~/fids/tls"
scp_any -r "$STAGE/clients/code.tgz" "$STAGE/clients/vm_setup.sh" "$STAGE/clients/self_deallocate.sh" "$STAGE/clients/data" "$ADMIN@$CLIENTS_IP:fids/"
scp_any "$STAGE/clients/ca.crt" "$ADMIN@$CLIENTS_IP:fids/tls/"

on_server "bash ~/fids/vm_setup.sh server" & P1=$!
on_clients "bash ~/fids/vm_setup.sh clients" & P2=$!
wait $P1; wait $P2
echo "[deploy] both VMs ready"
