#!/usr/bin/env bash
# Deallocate both VMs (stops compute billing; disks and static IPs still cost a little).
set -euo pipefail
RG=${RG:-fids-rg}
az vm deallocate -g "$RG" --ids $(az vm list -g "$RG" --query "[].id" -o tsv) -o none
az vm list -d -g "$RG" --query "[].{name:name, power:powerState}" -o table
