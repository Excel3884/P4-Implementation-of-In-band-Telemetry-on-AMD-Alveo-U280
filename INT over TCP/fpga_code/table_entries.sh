#!/bin/bash

SN_P4_CMD="sn-p4 --tls-insecure insert table rule"

if [[ $# -ne 1 || ( $1 != "default" && $1 != "backup" ) ]]; then
  echo "Usage: $0 <default|backup>"
  exit 1
fi

SW=$1

configure_ipv4_routing() {
  printf "\n\nConfiguring ipv4_routing table...\n"
  if [[ $SW == "default" ]]; then
    $SN_P4_CMD -t ipv4_routing -m 0x0a000001/32 --action ipv4_forward --param "0xB8CEF6AF8556 0"
    $SN_P4_CMD -t ipv4_routing -m 0x0a000002/32 --action ipv4_forward --param "0xB8CEF6AF8557 1"
  elif [[ $SW == "backup" ]]; then
    $SN_P4_CMD -t ipv4_routing -m 0x0a000001/32 --action ipv4_forward --param "0xB8CEF6AF8342 0"
    $SN_P4_CMD -t ipv4_routing -m 0x0a000002/32 --action ipv4_forward --param "0xE8EBD324F2B2 1"
  fi
}

configure_traffic_origin() {
  printf "\nConfiguring traffic_origin table \n"
    $SN_P4_CMD -t traffic_origin -m 0 --action get_port --param 0
}

configure_specs_retrieval() {
	printf"\nConfiguring specs_retrieval table for $SW path...\n"
  if [[ $SW == "default" ]]; then
	$SN_P4_CMD -t specs_retrieval -m 0 --action get_specs --param "2 7 5 2"
  elif [[ $SW == "backup" ]]; then
	$SN_P4_CMD -t specs_retrieval -m 0 --action get_specs --param "2 7 5 2"
  fi
}

# configure_l2_forwarding() {

# }

# Clear the table before applying configuration
sn-p4 --tls-insecure clear table
# Call configuration functions
configure_ipv4_routing
configure_specs_retrieval
configure_traffic_origin
# configure_l2_forwarding

printf "\n\n\nP4 table configuration completed for $SW\n"

sn-cfg configure port --state enable
# All egress packets are transmitted by the 100G pluggable module associated with each port.
sn-cfg configure switch -e 0:physical \
                        -e 1:physical

# Receive packets from the 100G pluggable module associated with each port and direct them to the user application for processing.
sn-cfg configure switch -i 0:physical:app \
			-i 1:physical:app \
                        -b straight
printf "\n Configured FPGA for normal operation\n"


