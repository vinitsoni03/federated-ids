#!/usr/bin/env bash
# Shared settings for the Azure scripts (sourced, not executed).
export MSYS_NO_PATHCONV=1   # Git Bash: keep /home/... and /subscriptions/... arguments as they are
RG=${RG:-fids-rg}
KEYDIR=${KEYDIR:-D:/federated-ids-work/azure}
TLS=${TLS:-$KEYDIR/tls}
ADMIN=${ADMIN:-fids}
DATA=${DATA:-D:/federated-ids-work/flower_data/category_iid_s0}
N_CLIENTS=${N_CLIENTS:-10}
AZURE_CLIENTS=${AZURE_CLIENTS:-"0 1 2 3 4"}     # partition ids run on the Azure client VM
LAPTOP_CLIENTS=${LAPTOP_CLIENTS:-"5 6 7 8 9"}   # partition ids run on this laptop
SERVER_PRIV=10.20.1.4
SSH_OPTS=(-i "$KEYDIR/id_ed25519" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KEYDIR/known_hosts"
          -o ServerAliveInterval=30)

server_ip()  { az vm show -d -g "$RG" -n fids-server  --query publicIps -o tsv; }
clients_ip() { az vm show -d -g "$RG" -n fids-clients --query publicIps -o tsv; }
# SSH runs on port 443: the operator's network blocks ~50 % of outbound port-22 connections
# (one of its two ISP links), while 443 always passes. The NSG allows only tcp/443 from the
# operator's two ISP exit addresses.
SSH_PORT=${SSH_PORT:-443}
SERVER_IP=${SERVER_IP:-$(server_ip)}
CLIENTS_IP=${CLIENTS_IP:-$(clients_ip)}
on_server()  { ssh -p "$SSH_PORT" "${SSH_OPTS[@]}" "$ADMIN@$SERVER_IP" "$@"; }
on_clients() { ssh -p "$SSH_PORT" "${SSH_OPTS[@]}" "$ADMIN@$CLIENTS_IP" "$@"; }
scp_any()    { scp -P "$SSH_PORT" "${SSH_OPTS[@]}" "$@"; }   # targets: $ADMIN@$SERVER_IP:path / $ADMIN@$CLIENTS_IP:path
