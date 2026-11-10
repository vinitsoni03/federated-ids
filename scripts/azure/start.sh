#!/usr/bin/env bash
# Start both VMs. The NSG rule is NOT changed here: it allows tcp/443 from the operator's two ISP
# exit addresses (a student decision). If the current public IP is not in that list, the script
# warns and stops so the rule can be changed deliberately.
set -euo pipefail
export MSYS_NO_PATHCONV=1
RG=${RG:-fids-rg}
MYIP=${MYIP:-$(curl -s --max-time 10 https://api.ipify.org)}
ALLOWED=$(az network nsg rule show -g "$RG" --nsg-name fids-nsg -n allow-ssh-operator \
  --query "[sourceAddressPrefix, sourceAddressPrefixes[]] | [] | [?@ != null]" -o tsv | tr -d '\r' | tr '\n\t' '  ')
if [[ " $ALLOWED " != *" $MYIP/32 "* && " $ALLOWED " != *" $MYIP "* ]]; then
  echo "Current public IP $MYIP is not allowed by the NSG (allowed: $ALLOWED). Not starting." >&2
  exit 1
fi
az vm start --ids $(az vm list -g "$RG" --query "[].id" -o tsv) -o none
echo "SSH (tcp/443) allowed from: $ALLOWED (current IP $MYIP)"
az vm list -d -g "$RG" --query "[].{name:name, power:powerState, ip:publicIps}" -o table
