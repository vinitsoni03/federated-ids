#!/usr/bin/env bash
# Runs ON a VM from cron (installed by vm_setup.sh): deallocates THIS VM through the Azure
# Resource Manager API using the VM's managed identity (role: Virtual Machine Contributor,
# scoped to the project resource group only). Safety net against forgotten running VMs.
set -euo pipefail
IMDS=http://169.254.169.254/metadata
TOKEN=$(curl -s -H Metadata:true "$IMDS/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
read -r SUB RG NAME < <(curl -s -H Metadata:true "$IMDS/instance/compute?api-version=2021-02-01" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['subscriptionId'], d['resourceGroupName'], d['name'])")
echo "$(date -u +%FT%TZ) deallocating $NAME in $RG"
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Length: 0" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/$NAME/deallocate?api-version=2024-07-01"
