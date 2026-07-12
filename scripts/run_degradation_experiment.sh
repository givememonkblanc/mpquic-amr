#!/usr/bin/env bash
# run_degradation_experiment.sh — gradual Wi‑Fi degradation via iptables packet loss + iperf3
# Demonstrates PQI's proactive degradation detection (reviewer R1/R3 requirement)
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env}"
# Deployment truth: SERVER_IP=192.168.0.38, EDGE_PROJECT_DIR, Tailscale SSH_ADDRESS.
source "${SCRIPT_DIR}/exp_env.sh"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RUN_DIR="${RUN_DIR:-${ROOT_DIR}/results/experiment_runs/${RUN_ID}}"
FRAMES_DIR="${FRAMES_DIR:-${RUN_DIR}/frames}"
SERVER_LOG="${SERVER_LOG:-${RUN_DIR}/server.log}"
CLIENT_LOG="${CLIENT_LOG:-${RUN_DIR}/edge_client.log}"
DEGRADE_LOG="${DEGRADE_LOG:-${RUN_DIR}/degradation_ramp.log}"
SVR_PREVIEW="${SVR_PREVIEW:-0}"
SVR_SAVE_FRAMES="${SVR_SAVE_FRAMES:-1}"
SVR_PREVIEW_CMD="${SVR_PREVIEW_CMD:-}"

# Single server IP; backup path goes through Tailscale subnet routing
SERVER_IP="${SERVER_IP:-192.168.0.38}"
PORT="${PORT:-4433}"

EDGE_PROJECT_DIR="${EDGE_PROJECT_DIR:-/home/jetson/mpquic}"
EDGE_WIRED_IFACE="${EDGE_WIRED_IFACE:-eno1}"
DISABLE_EDGE_WIRED_IFACE="${DISABLE_EDGE_WIRED_IFACE:-0}"
SKIP_EDGE_ROUTE_SETUP="${SKIP_EDGE_ROUTE_SETUP:-0}"

CLIENT_BIN_NAME="${CLIENT_BIN_NAME:-client_uploader}"
CLIENT_BIN="${CLIENT_BIN:-${EDGE_PROJECT_DIR}/build_d20/${CLIENT_BIN_NAME}}"
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
EDGE_HOTSPOT_IFACE="${EDGE_HOTSPOT_IFACE:-enx924cc5c9a35f}"
RUNTIME_SEC="${RUNTIME_SEC:-50}"          # 5s startup + 30s ramp + 15s recovery
DEGRADE_START_SEC="${DEGRADE_START_SEC:-5}"

# iptables loss ramp: loss_pct(%) duration(s)
# Targets only picoquic UDP packets to SERVER_IP:PORT on WiFi interface
# SSH (to our local machine) is NOT affected
RAMP_STEPS=(
  "1:5"
  "3:5"
  "5:5"
  "10:5"
  "20:10"
)
# After ramp: clear iptables → recovery for 15s

die(){ printf '[!] %s\n' "$*" >&2; exit 1; }

[ -f "$ENV_FILE" ] || die "env file not found: $ENV_FILE"
mkdir -p "$RUN_DIR" "$FRAMES_DIR"

# Parse .env via Python (same as run_handover_experiment.sh)
SSH_ADDRESS="${SSH_ADDRESS:-$(python3 -c "
import re
with open('$ENV_FILE') as f:
    text = f.read()
vals = {m.group(1): m.group(2) for m in re.finditer(r'^(ssh_address|ssh_id|ssh_password)\s*=\s*[\x27\"]([^\x27\"]+)[\x27\"]\s*$', text, re.M)}
print(vals['ssh_address'])
")}"
SSH_ID="${SSH_ID:-$(python3 -c "
import re
with open('$ENV_FILE') as f:
    text = f.read()
vals = {m.group(1): m.group(2) for m in re.finditer(r'^(ssh_address|ssh_id|ssh_password)\s*=\s*[\x27\"]([^\x27\"]+)[\x27\"]\s*$', text, re.M)}
print(vals['ssh_id'])
")}"
SSH_PASSWORD="${SSH_PASSWORD:-$(python3 -c "
import re
with open('$ENV_FILE') as f:
    text = f.read()
vals = {m.group(1): m.group(2) for m in re.finditer(r'^(ssh_address|ssh_id|ssh_password)\s*=\s*[\x27\"]([^\x27\"]+)[\x27\"]\s*$', text, re.M)}
print(vals['ssh_password'])
")}"
[ -n "$SSH_PASSWORD" ] || die "SSH_PASSWORD not set in $ENV_FILE"

ssh_edge(){
  local cmd="$1"
  sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=$HOME/.ssh/known_hosts "${SSH_ID}@${SSH_ADDRESS}" "$cmd"
}

setup_policy_routing(){
  [ "$SKIP_EDGE_ROUTE_SETUP" = "1" ] && return 0
  if ! sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=$HOME/.ssh/known_hosts "${SSH_ID}@${SSH_ADDRESS}" \
    "echo '${SSH_PASSWORD}' | sudo -S sh -lc 'ip rule del from ${EDGE_WIFI_IP}/32 table 100 2>/dev/null || true; ip route flush table 100 2>/dev/null || true; ip route add ${SERVER_IP}/32 via 192.168.0.1 dev ${EDGE_WIFI_IFACE} table 100; ip rule add from ${EDGE_WIFI_IP}/32 table 100 priority 1000;'"; then
    echo "[*] policy routing unsupported; falling back to direct Wi‑Fi host route"
    sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=$HOME/.ssh/known_hosts "${SSH_ID}@${SSH_ADDRESS}" \
      "echo '${SSH_PASSWORD}' | sudo -S sh -lc 'ip route del ${SERVER_IP}/32 via 165.229.169.1 dev ${EDGE_WIRED_IFACE} 2>/dev/null || true; ip route del ${SERVER_IP}/32 dev ${EDGE_WIRED_IFACE} 2>/dev/null || true; ip route replace ${SERVER_IP}/32 dev ${EDGE_WIFI_IFACE} src ${EDGE_WIFI_IP} metric 5'" \
      || die "failed to install fallback Wi-Fi host route"
  fi
}

cleanup_policy_routing(){
  [ "$SKIP_EDGE_ROUTE_SETUP" = "1" ] && return 0
  sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=$HOME/.ssh/known_hosts "${SSH_ID}@${SSH_ADDRESS}" \
    "echo '${SSH_PASSWORD}' | sudo -S sh -lc 'ip rule del from ${EDGE_WIFI_IP}/32 table 100 2>/dev/null || true; ip route flush table 100 2>/dev/null || true'" 2>/dev/null || true
}

require_edge_interface(){
  local iface="$1"
  ssh_edge "ip link show $iface" >/dev/null 2>&1 || die "required edge interface missing: $iface"
}

disable_edge_wired_iface(){
  [ "$DISABLE_EDGE_WIRED_IFACE" = "1" ] || return 0
  sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=$HOME/.ssh/known_hosts "${SSH_ID}@${SSH_ADDRESS}" \
    "echo '${SSH_PASSWORD}' | sudo -S ip link set ${EDGE_WIRED_IFACE} down"
}

enable_edge_wired_iface(){
  [ "$DISABLE_EDGE_WIRED_IFACE" = "1" ] || return 0
  sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=$HOME/.ssh/known_hosts "${SSH_ID}@${SSH_ADDRESS}" \
    "echo '${SSH_PASSWORD}' | sudo -S ip link set ${EDGE_WIRED_IFACE} up" 2>/dev/null || true
}

cleanup(){
  echo "[*] cleanup ..."
  kill "$SERVER_PID" 2>/dev/null || true
  enable_edge_wired_iface
  cleanup_policy_routing
  # Clear all iptables rules on wifi interface
  ssh_edge "echo '${SSH_PASSWORD}' | sudo -S iptables -F OUTPUT 2>/dev/null; echo 'cleaned up'" 2>/dev/null || true
  ssh_edge "killall client_uploader client_uploader_baseline client_uploader_minrtt client_uploader_rr 2>/dev/null; true" 2>/dev/null || true
}
trap cleanup EXIT

# ── 1. Ensure iptables are clean on Jetson WiFi interface ──
ssh_edge "echo '${SSH_PASSWORD}' | sudo -S iptables -F OUTPUT 2>/dev/null; echo 'iptables OK'" 2>/dev/null || true

# ── 2. Start picoquic server ──
TUNE_RP_FILTER=0 SVR_PREVIEW="$SVR_PREVIEW" SVR_SAVE_FRAMES="$SVR_SAVE_FRAMES" SVR_PREVIEW_CMD="$SVR_PREVIEW_CMD" OUT_DIR="$FRAMES_DIR" timeout "$((RUNTIME_SEC + 20))s" bash "${SCRIPT_DIR}/run_server.sh" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 1
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  die "server failed to start — check $SERVER_LOG"
fi
echo "[*] picoquic server started (PID $SERVER_PID)"

# ── 2.5. Install temporary source-policy routing on edge ──
require_edge_interface "$EDGE_WIFI_IFACE"
require_edge_interface "$EDGE_HOTSPOT_IFACE"
disable_edge_wired_iface
setup_policy_routing

# ── 3. Start Jetson client ──
echo "[*] starting client ($MODE_LABEL) on edge ..."
ssh_edge "killall ${CLIENT_BIN_NAME} iperf3 2>/dev/null; true"
sleep 0.5
# client_uploader argv contract:
#   <server_ip> <primary_local_ip> [port] [backup_local_ip]
# Primary: WiFi (192.168.0.13 → 192.168.0.38 direct)
# Backup:  Tailscale (100.109.159.8 → 192.168.0.38 via subnet route)
# NOTE: env requires VAR=value form (old form tried to exec "MPQUIC_SCHED_MODE"
# as a command → mode never applied); duration pinned to RUNTIME_SEC (client
# internal default is 30 s and would truncate the 50 s degradation ramp).
ssh_edge "env MPQUIC_SCHED_MODE='${SCHED_MODE}' MPQUIC_EXP_DURATION_US=$((RUNTIME_SEC * 1000000)) timeout ${RUNTIME_SEC}s '${CLIENT_BIN}' '${SERVER_IP}' '${EDGE_WIFI_IP}' '${PORT}' '${EDGE_HOTSPOT_IP}'" >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
sleep 2

echo "[*] client started, waiting ${DEGRADE_START_SEC}s before degradation ramp ..."
sleep "$((DEGRADE_START_SEC - 2))"

# ── 4. Gradual iptables loss ramp on Wi‑Fi (picoquic packets only) ──
IPTABLES_PREFIX="echo '${SSH_PASSWORD}' | sudo -S iptables"
IPTABLES_MATCH="-A OUTPUT -o ${EDGE_WIFI_IFACE} -p udp --dport ${PORT} -d ${SERVER_IP}"
IPTABLES_CLEAR="echo '${SSH_PASSWORD}' | sudo -S iptables -F OUTPUT"

total_ramp_dur=0
{
  echo "=== degradation ramp start $(date -Iseconds) ==="
  echo "target: ${SERVER_IP}:${PORT} on ${EDGE_WIFI_IFACE}"
  echo "ramp steps:"
  for step in "${RAMP_STEPS[@]}"; do
    pct="${step%%:*}"
    dur="${step##*:}"
    echo "  ${pct}% loss for ${dur}s"
  done
  echo ""

  for step in "${RAMP_STEPS[@]}"; do
    pct="${step%%:*}"
    dur="${step##*:}"
    prob=$(echo "scale=2; $pct / 100" | bc)
    echo "--- step: ${pct}% loss for ${dur}s (prob=${prob}) ---"
    # Clear previous rules, then add new loss rule
    ssh_edge "${IPTABLES_CLEAR}" 2>/dev/null || true
    sleep 0.2
    ssh_edge "${IPTABLES_PREFIX} ${IPTABLES_MATCH} -m statistic --mode random --probability ${prob} -j DROP" 2>&1 || true
    sleep "${dur}"
    total_ramp_dur=$((total_ramp_dur + dur))
    echo "--- step ${pct}% done ---"
  done
  # Clear iptables (recovery)
  echo "=== clearing iptables, recovering for 15s ==="
  ssh_edge "${IPTABLES_CLEAR}" 2>/dev/null || true
  sleep 15
  echo "=== experiment end $(date -Iseconds) ==="
} >> "$DEGRADE_LOG" 2>&1 &
DEGRADE_PID=$!

echo "[*] degradation ramp running ($total_ramp_dur s total), PID=$DEGRADE_PID"
echo "    log: $DEGRADE_LOG"
echo "    run_dir: $RUN_DIR"

# ── 5. Wait for client to finish ──
wait "$CLIENT_PID" 2>/dev/null || true
wait "$DEGRADE_PID" 2>/dev/null || true

# ── 6. Collect results summary ──
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Gradual Degradation Experiment — $MODE_LABEL    ║"
echo "╚══════════════════════════════════════════════════════╝"
printf '│  Run:       %-43s │\n' "$RUN_ID"
printf '│  Mode:      %-43s │\n' "$MODE_LABEL"
printf '│  Duration:  %-43s │\n' "${RUNTIME_SEC}s"
printf '│  Ramp:      %-43s │\n' "iptables loss on ${EDGE_WIFI_IFACE}"
echo "├──────────────────────────────────────────────────────┤"
echo "│  Ramp profile (iptables packet loss on picoquic):    │"
for step in "${RAMP_STEPS[@]}"; do
  pct="${step%%:*}"
  dur="${step##*:}"
  printf '│    %2s%% loss for %2s seconds                         │\n' "$pct" "$dur"
done
echo "│    then 15s recovery                                  │"
echo "├──────────────────────────────────────────────────────┤"
echo "│  Serv. log:    $SERVER_LOG │"
echo "│  Clnt. log:    $CLIENT_LOG │"
echo "│  Ramp log:     $DEGRADE_LOG  │"
echo "╰──────────────────────────────────────────────────────╯"

# Quick summary from client log
if [ -f "$CLIENT_LOG" ]; then
  echo ""
  echo "=== Client log summary ==="
  grep -E 'total frames|total throughput|max gap|PQI_SWITCH|avg_goodput|frames written|handshake complete|\[PATH-SELECT\]|\[RSSI\]' "$CLIENT_LOG" | tail -20
fi

echo ""
echo "[*] done — results in $RUN_DIR"
