#!/bin/bash
sn-cfg batch configure-switch -s port0:port0 -s port1:port1 -s host0:host0 -s host1:host1
sn-cfg batch configure-switch -i port0:app0 -i port1:app0
sn-cfg batch configure-switch -e app0:port0:port0 -e app0:port1:port1

sn-cfg --tls-insecure batch configure-port -p 0 -s enable
sn-cfg --tls-insecure batch configure-port -p 1 -s enable

sn-cfg batch show-switch-config
