#!/bin/sh
# Linux host packet capture; run separately from the unprivileged sensor.
set -eu
if [ "$#" -ne 2 ]; then
  echo 'Usage: sudo sh scripts/capture.sh INTERFACE OUTPUT_DIRECTORY' >&2
  exit 2
fi
mkdir -p "$2"
chmod 700 "$2"
# 32 x 100 MB ring; includes TCP handshakes, rejected connections, TLS bytes.
# tcpdump drops privileges to tcpdump on many distros: make the directory
# writable by that account first, or use the local distro capture service.
exec tcpdump -i "$1" -n -s 0 -U -C 100 -W 32 -w "$2/traffic.pcap" 'tcp port 8080 or tcp port 8443'
