#!/usr/bin/env bash
# run_handover_experiment.sh — full handover test with Wi-Fi disconnect/reconnect
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RUN_DIR="${RUN_DIR:-${ROOT_DIR}/experiment_runs/${RUN_ID}}"
FRAMES_DIR="${FRAMES_DIR:-${RUN_DIR}/frames}"
SERVER_LOG="${SERVER_LOG:-${RUN_DIR}/server.log}"
CLIENT_LOG="${CLIENT_LOG:-${RUN_DIR}/edge_client.log}"
SVR_PREVIEW="${SVR_PREVIEW:-0}"
SVR_SAVE_FRAMES="${SVR_SAVE_FRAMES:-1}"
SVR_PREVIEW_CMD="${SVR_PREVIEW_CMD:-}"

# ── Single server IP; backup path goes through Tailscale subnet routing ──
SERVER_IP="${SERVER_IP:-192.168.0.80}"
PORT="${PORT:-4433}"

EDGE_PROJECT_DIR="${EDGE_PROJECT_DIR:-/home/jetson/client_multi_path_enhanced}"
EDGE_WIRED_IFACE="${EDGE_WIRED_IFACE:-eno1}"
DISABLE_EDGE_WIRED_IFACE="${DISABLE_EDGE_WIRED_IFACE:-0}"
SKIP_EDGE_ROUTE_SETUP="${SKIP_EDGE_ROUTE_SETUP:-0}"

# ── Binary selection ──
CLIENT_BIN_NAME="${CLIENT_BIN_NAME:-client_uploader}"
CLIENT_BIN="${CLIENT_BIN:-${EDGE_PROJECT_DIR}/build/${CLIENT_BIN_NAME}}"
SCHED_MODE="${MPQUIC_SCHED_MODE:-rssi}"
case "$SCHED_MODE" in
  rssi)    MODE_LABEL="RSSI" ;;
  pqi)     MODE_LABEL="PQI" ;;
  default) MODE_LABEL="DEFAULT" ;;
  spquic)  MODE_LABEL="SPQUIC" ;;
  *)
    case "$CLIENT_BIN_NAME" in
      *baseline) MODE_LABEL="BASELINE" ;;
      *minrtt)   MODE_LABEL="MINRTT"   ;;
      *rr)       MODE_LABEL="RR"       ;;
      *)         MODE_LABEL="${SCHED_MODE}" ;;
    esac
    ;;
esac
EDGE_WIFI_IFACE="${EDGE_WIFI_IFACE:-wlP1p1s0}"
EDGE_WIFI_IP="${EDGE_WIFI_IP:-192.168.0.13}"
EDGE_HOTSPOT_IP="${EDGE_HOTSPOT_IP:-172.20.10.3}"
RUNTIME_SEC="${RUNTIME_SEC:-30}"
HANDOVER_AT_SEC="${HANDOVER_AT_SEC:-10}"
FAILBACK_AFTER_SEC="${FAILBACK_AFTER_SEC:-8}"

die(){ printf '[!] %s\n' "$*" >&2; exit 1; }

[ -f "$ENV_FILE" ] || die "env file not found: $ENV_FILE"
mkdir -p "$RUN_DIR" "$FRAMES_DIR"

# ── Parse credentials ──
SSH_ADDRESS="${SSH_ADDRESS:-$(python3 -c "
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
vals = {m.group(1): m.group(2) for m in re.finditer(r'^(ssh_address|ssh_id|ssh_password)\s*=\s*[\x27\"]([^\x27\"]+)[\x27\"]\s*$', text, re.M)}
print(vals['ssh_address'])
" "$ENV_FILE")}"
SSH_ID="${SSH_ID:-$(python3 -c "
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
vals = {m.group(1): m.group(2) for m in re.finditer(r'^(ssh_address|ssh_id|ssh_password)\s*=\s*[\x27\"]([^\x27\"]+)[\x27\"]\s*$', text, re.M)}
print(vals['ssh_id'])
" "$ENV_FILE")}"
SSH_PASSWORD="${SSH_PASSWORD:-$(python3 -c "
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
vals = {m.group(1): m.group(2) for m in re.finditer(r'^(ssh_address|ssh_id|ssh_password)\s*=\s*[\x27\"]([^\x27\"]+)[\x27\"]\s*$', text, re.M)}
print(vals['ssh_password'])
" "$ENV_FILE")}"

ssh_edge() {
    # Combine all args into one quoted string so SSH preserves quoting on the remote side
    local cmd=""
    for arg in "$@"; do
        if [[ "$arg" =~ \  ]]; then
            cmd="$cmd '$arg'"
        else
            cmd="$cmd $arg"
        fi
    done
    sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/opencode/known_hosts "${SSH_ID}@${SSH_ADDRESS}" "$cmd"
}

setup_policy_routing() {
    [ "$SKIP_EDGE_ROUTE_SETUP" = "1" ] && return 0
    if ! sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/opencode/known_hosts "${SSH_ID}@${SSH_ADDRESS}" \
      "echo '$SSH_PASSWORD' | sudo -S sh -lc 'ip rule del from ${EDGE_WIFI_IP}/32 table 100 2>/dev/null || true; ip route flush table 100 2>/dev/null || true; ip route add ${SERVER_IP}/32 via 192.168.0.1 dev ${EDGE_WIFI_IFACE} table 100; ip rule add from ${EDGE_WIFI_IP}/32 table 100 priority 1000;'"; then
        printf '[*] policy routing unsupported; falling back to direct Wi-Fi host route\n'
        sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/opencode/known_hosts "${SSH_ID}@${SSH_ADDRESS}" \
          "echo '$SSH_PASSWORD' | sudo -S sh -lc 'ip route del ${SERVER_IP}/32 via 165.229.169.1 dev ${EDGE_WIRED_IFACE} 2>/dev/null || true; ip route del ${SERVER_IP}/32 dev ${EDGE_WIRED_IFACE} 2>/dev/null || true; ip route replace ${SERVER_IP}/32 dev ${EDGE_WIFI_IFACE} src ${EDGE_WIFI_IP} metric 5'" \
          || die "failed to install fallback Wi-Fi host route"
    fi
}

cleanup_policy_routing() {
    [ "$SKIP_EDGE_ROUTE_SETUP" = "1" ] && return 0
    sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/opencode/known_hosts "${SSH_ID}@${SSH_ADDRESS}" \
      "echo '$SSH_PASSWORD' | sudo -S sh -lc 'ip rule del from ${EDGE_WIFI_IP}/32 table 100 2>/dev/null || true; ip route flush table 100 2>/dev/null || true'" 2>/dev/null || true
}

require_edge_interface() {
    local iface="$1"
    ssh_edge ip link show "$iface" >/dev/null 2>&1 || die "required edge interface missing: $iface"
}

disable_edge_wired_iface() {
    [ "$DISABLE_EDGE_WIRED_IFACE" = "1" ] || return 0
    sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/opencode/known_hosts "${SSH_ID}@${SSH_ADDRESS}" \
      "echo '$SSH_PASSWORD' | sudo -S ip link set ${EDGE_WIRED_IFACE} down"
}

enable_edge_wired_iface() {
    [ "$DISABLE_EDGE_WIRED_IFACE" = "1" ] || return 0
    sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/opencode/known_hosts "${SSH_ID}@${SSH_ADDRESS}" \
      "echo '$SSH_PASSWORD' | sudo -S ip link set ${EDGE_WIRED_IFACE} up" 2>/dev/null || true
}

# ── Print config ──
printf '┌─────────────────────────────────────────────────┐\n'
printf '│  HANDOVER EXPERIMENT  %-37s │\n' "$RUN_ID"
printf '├─────────────────────────────────────────────────┤\n'
printf '│  Server:    %-43s │\n' "${SERVER_IP}:${PORT}"
printf '│  Edge:      %-43s │\n' "${SSH_ID}@${SSH_ADDRESS}"
printf '│  Wi‑Fi:     %-23s → %-14s │\n' "$EDGE_WIFI_IFACE" "$EDGE_WIFI_IP"
printf '│  Hotspot:   %-23s → %-14s │\n' "enx924cc5c9a35f" "$EDGE_HOTSPOT_IP"
printf '│  Mode:      %-43s │\n' "$MODE_LABEL"
printf '│  Runtime:   %-10s  Handover@+%ss  Reconnect@+%ss │\n' "${RUNTIME_SEC}s" "${HANDOVER_AT_SEC}" "$((HANDOVER_AT_SEC + FAILBACK_AFTER_SEC))"
printf '│  Frames →   %-43s │\n' "$FRAMES_DIR"
printf '└─────────────────────────────────────────────────┘\n'

# ── 1. Start server ──
TUNE_RP_FILTER=0 SVR_PREVIEW="$SVR_PREVIEW" SVR_SAVE_FRAMES="$SVR_SAVE_FRAMES" SVR_PREVIEW_CMD="$SVR_PREVIEW_CMD" OUT_DIR="$FRAMES_DIR" timeout "$((RUNTIME_SEC + 20))s" bash "${SCRIPT_DIR}/run_server.sh" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
# NOTE: edge has no passwordless sudo — use `sudo -S` with the ssh password
# (same pattern as run_degradation_experiment.sh). Con name is parametrized.
EDGE_WIFI_CON_NAME="${EDGE_WIFI_CON_NAME:-solfac 220 5G}"
trap 'kill "$SERVER_PID" >/dev/null 2>&1 || true; enable_edge_wired_iface; cleanup_policy_routing; ssh_edge "echo '"'"'${SSH_PASSWORD}'"'"' | sudo -S nmcli con up \"${EDGE_WIFI_CON_NAME}\"" 2>/dev/null || true' EXIT

sleep 3
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    die "server failed to start — check $SERVER_LOG"
fi
printf '[*] Server started (PID %d)\n' "$SERVER_PID"

# ── Install temporary source-policy routing on edge ──
require_edge_interface "$EDGE_WIFI_IFACE"
require_edge_interface "enx924cc5c9a35f"
disable_edge_wired_iface
setup_policy_routing

# ── 2. Start edge client ──
# client_uploader argv contract:
#   <server_ip> <primary_local_ip> [port] [backup_local_ip]
# Primary: WiFi (192.168.0.13 → 192.168.0.80 direct)
# Backup:  Tailscale (100.109.159.8 → 192.168.0.80 via subnet route)
# NOTE: env requires VAR=value form — the old `env MPQUIC_SCHED_MODE "$SCHED_MODE"`
# made env try to EXECUTE "MPQUIC_SCHED_MODE" as a command (mode never applied).
# Duration is pinned to RUNTIME_SEC: the client's internal default is 30 s and
# silently truncated longer runs.
ssh_edge env "MPQUIC_SCHED_MODE=${SCHED_MODE}" "MPQUIC_EXP_DURATION_US=$((RUNTIME_SEC * 1000000))" timeout "${RUNTIME_SEC}s" "${CLIENT_BIN}" "${SERVER_IP}" "${EDGE_WIFI_IP}" "${PORT}" "${EDGE_HOTSPOT_IP}" >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
printf '[*] Edge client started (PID %d) — %s\n' "$CLIENT_PID" "$CLIENT_BIN_NAME"

# ── 3. Wait for handover point, then disconnect Wi‑Fi ──
sleep "$HANDOVER_AT_SEC"
printf '[*] *** HANDOVER: disconnect Wi‑Fi (%s) ***\n' "$EDGE_WIFI_IFACE"
ssh_edge "echo '${SSH_PASSWORD}' | sudo -S nmcli device disconnect ${EDGE_WIFI_IFACE}" 2>&1 | head -5 || true

# ── 4. Wait, then reconnect Wi‑Fi ──
sleep "$FAILBACK_AFTER_SEC"
printf '[*] *** FAILBACK: reconnect Wi‑Fi ***\n'
ssh_edge "echo '${SSH_PASSWORD}' | sudo -S nmcli con up \"${EDGE_WIFI_CON_NAME}\"" 2>&1 | head -5 || true

# ── 5. Wait for client/server to finish ──
wait "$CLIENT_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
enable_edge_wired_iface
cleanup_policy_routing
trap - EXIT

# ── 6. Results ──
FRAME_COUNT="$(python3 -c "
import glob, pathlib, sys
root = pathlib.Path('$FRAMES_DIR')
count = len(glob.glob(str(root / 'frame_*.jpg'))) + len(glob.glob(str(root / 'frame_*.png')))
print(count)
")"

printf '┌─────────────────────────────────────────────────┐\n'
printf '│  EXPERIMENT COMPLETE                            │\n'
printf '├─────────────────────────────────────────────────┤\n'
printf '│  Frames received:  %-35d │\n' "$FRAME_COUNT"
printf '│  Artifacts:        %-35s │\n' "$RUN_DIR"
printf '└─────────────────────────────────────────────────┘\n'

printf '\n── PQI events ──\n'
grep -E '\[PQI_METRIC\]|\[PQI\]|\[PQI_SWITCH\]' "$CLIENT_LOG" 2>/dev/null | tail -40 || echo '(none found)'

printf '\n── EXP events ──\n'
grep -E 'EXP_|handshake complete|\[PATH-SELECT\]|\[RSSI\]' "$CLIENT_LOG" 2>/dev/null | tail -20 || echo '(none found)'

printf '\n── Last 20 log lines ──\n'
tail -20 "$CLIENT_LOG" 2>/dev/null || echo '(empty)'

printf '\n[*] Artifacts: %s\n' "$RUN_DIR"
printf '[*] Full client log: %s\n' "$CLIENT_LOG"
