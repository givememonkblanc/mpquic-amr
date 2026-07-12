#!/usr/bin/env bash
set -Eeuo pipefail

# Legacy helper replaced with source-policy routing for the WiFi (primary) path.
# Backup path now uses Tailscale subnet routing and does not need policy rules.
#
# Usage:
#   SERVER_IP=192.168.0.38 \
#   EDGE_WIFI_IFACE=wlP1p1s0 EDGE_WIFI_IP=192.168.0.13 \
#   sudo ./scripts/route_setup.sh

SERVER_IP="${SERVER_IP:-192.168.0.38}"
EDGE_WIFI_IFACE="${EDGE_WIFI_IFACE:-wlP1p1s0}"
EDGE_WIFI_IP="${EDGE_WIFI_IP:-192.168.0.13}"
EDGE_WIFI_GW="${EDGE_WIFI_GW:-192.168.0.1}"

ip rule del from "${EDGE_WIFI_IP}/32" table 100 2>/dev/null || true
ip route flush table 100 2>/dev/null || true

ip route add "${SERVER_IP}/32" via "${EDGE_WIFI_GW}" dev "${EDGE_WIFI_IFACE}" table 100
ip rule add from "${EDGE_WIFI_IP}/32" table 100 priority 1000

printf 'Configured source-policy routing\n'
printf '  primary: %s via %s (%s)\n' "${EDGE_WIFI_IP}" "${EDGE_WIFI_GW}" "${EDGE_WIFI_IFACE}"
printf '  destination: %s\n' "${SERVER_IP}"
