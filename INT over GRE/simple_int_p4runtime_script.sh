#!/bin/bash

SN_P4_CMD="sn-p4 --tls-insecure insert table rule"

if [[ $# -ne 1 || ( $1 != "s1" && $1 != "s2" ) ]]; then
  echo "Usage: $0 <s1|s2>"
  exit 1
fi

SW=$1

configure_int_operation() {
  printf "\nConfiguring int_operation table for $SW...\n"
  if [[ $SW == "s1" ]]; then
    $SN_P4_CMD -t int_operation -m 0x0001 --action sw0_push_id --param 0x101
    $SN_P4_CMD -t int_operation -m 0x0002 --action sw0_push_ingress_timestamp
    $SN_P4_CMD -t int_operation -m 0x0004 --action sw0_push_trust_level
  else
    $SN_P4_CMD -t int_operation -m 0x0001 --action sw1_push_id --param 0x201
    $SN_P4_CMD -t int_operation -m 0x0002 --action sw1_push_ingress_timestamp
    $SN_P4_CMD -t int_operation -m 0x0004 --action sw1_push_trust_level
  fi
}

configure_ipv4_routing() {
  printf "\n\nConfiguring ipv4_routing table...\n"
  if [[ $SW == "s1" ]]; then
    $SN_P4_CMD -t ipv4_routing -m 0xc0a80103 --action ipv4_forward --param "0x2A2B2C2D2E2F 1" # sink IP address is reached through port 1 and setting its mac
    $SN_P4_CMD -t ipv4_routing -m 0xc0a80102 --action ipv4_forward --param "0x06037910FC85 0" # source IP address is reached through port 0 and setting mac of next hop
  else
    $SN_P4_CMD -t ipv4_routing -m 0xc0a80103 --action ipv4_forward --param "0x06ADE2A934C9 1" # source IP address is reached through port 0 and setting its mac
    $SN_P4_CMD -t ipv4_routing -m 0xc0a80102 --action ipv4_forward --param "0x1A1B1C1D1E1F 0" # source IP address is reached through port 0 and setting mac of next hop
  fi
}

configure_l2_forwarding() {
  printf "\n\nConfiguring l2_forwarding table...\n"
  if [[ $SW == "s1" ]]; then
    $SN_P4_CMD -t l2_forwarding -m 0x2A2B2C2D2E2F --action l2_forward --param 1
    $SN_P4_CMD -t l2_forwarding -m 0x06037910FC85 --action l2_forward --param 0
  else
    $SN_P4_CMD -t l2_forwarding -m 0x06ADE2A934C9 --action l2_forward --param 1
    $SN_P4_CMD -t l2_forwarding -m 0x1A1B1C1D1E1F --action l2_forward --param 0
  fi
}

# Clear the table before applying configuration
sn-p4 --tls-insecure clear table
# Call configuration functions
configure_int_operation
configure_ipv4_routing
configure_l2_forwarding

printf "\n\n\nP4 table configuration completed for $SW\n"
