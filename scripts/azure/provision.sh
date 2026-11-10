#!/usr/bin/env bash
# Create the Azure resources for the hybrid Flower deployment + inference endpoint.
# Everything goes into ONE new resource group ($RG); nothing outside it is touched.
#
#   bash scripts/azure/provision.sh            # create (idempotent where az allows)
#
# Design (decided by the student, see PHASE2_PLAN.md "Azure deployment"):
#   * region indiasouthcentral, 2 x Standard_B2s_v2 (Ubuntu 24.04): fids-server, fids-clients
#   * NSG: inbound ONLY tcp/22 from the operator's current public IP; Flower (8000) and the
#     endpoint (8443) are never exposed and are reached through SSH tunnels
#   * key-only SSH with a dedicated key kept outside the repository ($KEYDIR)
#   * safety net: each VM has a managed identity with "Virtual Machine Contributor" scoped to
#     $RG only, and a cron job (installed by vm_setup.sh) deallocates it daily at 23:30 IST.
#     (Azure's built-in auto-shutdown is not available in indiasouthcentral.)
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash: do not rewrite /subscriptions/... arguments into Windows paths
RG=${RG:-fids-rg}
LOC=${LOC:-indiasouthcentral}
SIZE=${SIZE:-Standard_B2s_v2}
IMAGE=${IMAGE:-Canonical:ubuntu-24_04-lts:server:latest}
KEYDIR=${KEYDIR:-D:/federated-ids-work/azure}
ADMIN=${ADMIN:-fids}
MYIP=${MYIP:-$(curl -s --max-time 10 https://api.ipify.org)}
TAGS="project=federated-ids owner=E23CSEU0437 purpose=research"

mkdir -p "$KEYDIR"
if [ ! -f "$KEYDIR/id_ed25519" ]; then
  ssh-keygen -t ed25519 -N "" -C "fids-azure" -f "$KEYDIR/id_ed25519" >/dev/null
fi

echo "[provision] operator IP for SSH rule: $MYIP"
az group create -n "$RG" -l "$LOC" --tags $TAGS -o none
az network vnet create -g "$RG" -n fids-vnet --address-prefixes 10.20.0.0/16 \
  --subnet-name fids-subnet --subnet-prefixes 10.20.1.0/24 --tags $TAGS -o none
az network nsg create -g "$RG" -n fids-nsg --tags $TAGS -o none
az network nsg rule create -g "$RG" --nsg-name fids-nsg -n allow-ssh-operator --priority 100 \
  --direction Inbound --access Allow --protocol Tcp --destination-port-ranges 22 \
  --source-address-prefixes "$MYIP/32" -o none
az network vnet subnet update -g "$RG" --vnet-name fids-vnet -n fids-subnet --network-security-group fids-nsg -o none

for VM in fids-server fids-clients; do
  if az vm show -g "$RG" -n "$VM" -o none 2>/dev/null; then echo "[provision] $VM exists"; continue; fi
  PRIV=$([ "$VM" = fids-server ] && echo 10.20.1.4 || echo 10.20.1.5)
  az network public-ip create -g "$RG" -n "$VM-ip" --sku Standard --allocation-method Static --tags $TAGS -o none
  az network nic create -g "$RG" -n "$VM-nic" --vnet-name fids-vnet --subnet fids-subnet \
    --private-ip-address "$PRIV" --public-ip-address "$VM-ip" --tags $TAGS -o none
  az vm create -g "$RG" -n "$VM" --nics "$VM-nic" --size "$SIZE" --image "$IMAGE" \
    --admin-username "$ADMIN" --ssh-key-values "$KEYDIR/id_ed25519.pub" \
    --os-disk-size-gb 30 --storage-sku StandardSSD_LRS --tags $TAGS -o none
  echo "[provision] created $VM ($PRIV)"
done
RG_ID=$(az group show -n "$RG" --query id -o tsv)
for VM in fids-server fids-clients; do
  az vm identity assign -g "$RG" -n "$VM" --role "Virtual Machine Contributor" --scope "$RG_ID" -o none
  echo "[provision] $VM: managed identity with Virtual Machine Contributor on $RG"
done
az vm list-ip-addresses -g "$RG" -o table
