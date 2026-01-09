#!/bin/bash

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <switch_name>"
    exit 1
fi

SWITCH=$1

if [[ "$SWITCH" == "s1" ]]; then
    sn-cfg batch configure-switch -s port0:port0 -s port1:port1 -s host0:host0 -s host1:host1
    sn-cfg batch configure-switch -i port0:app0 -i port1:bypass
    sn-cfg batch configure-switch -e app0:port1:port1 -e bypass:port1:port0
elif [[ "$SWITCH" == "s2" ]]; then
    sn-cfg batch configure-switch -s port0:port0 -s port1:port1 -s host0:host0 -s host1:host1
    sn-cfg batch configure-switch -i port0:app0 -i port1:drop
    sn-cfg batch configure-switch -e app0:port1:port0
else
    echo "Unknown switch: $SWITCH"
    exit 1
fi

sn-cfg --tls-insecure batch configure-port -p 0 -s enable
sn-cfg --tls-insecure batch configure-port -p 1 -s enable
sn-cfg batch show-switch-config

echo "Configuration completed for $SWITCH."
