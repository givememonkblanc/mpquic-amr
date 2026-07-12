#!/usr/bin/env bash
# run_preview_stream.sh — real-camera live preview without per-frame file accumulation
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RUN_DIR="${RUN_DIR:-${ROOT_DIR}/results/experiment_runs/${RUN_ID}}"
SERVER_LOG="${SERVER_LOG:-${RUN_DIR}/server.log}"
CLIENT_LOG="${CLIENT_LOG:-${RUN_DIR}/edge_client.log}"

SERVER_IP="${SERVER_IP:-192.168.0.80}"
PORT="${PORT:-4433}"
RUNTIME_SEC="${RUNTIME_SEC:-20}"

EDGE_PROJECT_DIR="${EDGE_PROJECT_DIR:-/home/jetson/client_multi_path_enhanced}"
CLIENT_BIN_NAME="${CLIENT_BIN_NAME:-client_uploader}"
CLIENT_BIN="${CLIENT_BIN:-${EDGE_PROJECT_DIR}/build_d20/${CLIENT_BIN_NAME}}"
EDGE_WIFI_IP="${EDGE_WIFI_IP:-192.168.0.13}"
EDGE_HOTSPOT_IP="${EDGE_HOTSPOT_IP:-172.20.10.3}"

SVR_PREVIEW="${SVR_PREVIEW:-1}"
SVR_SAVE_FRAMES="${SVR_SAVE_FRAMES:-0}"
SVR_PREVIEW_CMD="${SVR_PREVIEW_CMD:-}"

die(){ printf '[!] %s\n' "$*" >&2; exit 1; }

[ -f "$ENV_FILE" ] || die "env file not found: $ENV_FILE"
mkdir -p "$RUN_DIR"

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

ssh_edge(){
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

printf '┌─────────────────────────────────────────────────┐\n'
printf '│  LIVE PREVIEW  %-41s│\n' "$RUN_ID"
printf '├─────────────────────────────────────────────────┤\n'
printf '│  Server:    %-43s │\n' "${SERVER_IP}:${PORT}"
printf '│  Edge:      %-43s │\n' "${SSH_ID}@${SSH_ADDRESS}"
printf '│  Runtime:   %-43s │\n' "${RUNTIME_SEC}s"
printf '│  Preview:   %-43s │\n' "SVR_PREVIEW=${SVR_PREVIEW}, SVR_SAVE_FRAMES=${SVR_SAVE_FRAMES}"
printf '└─────────────────────────────────────────────────┘\n'

TUNE_RP_FILTER=0 \
SVR_PREVIEW="$SVR_PREVIEW" \
SVR_SAVE_FRAMES="$SVR_SAVE_FRAMES" \
SVR_PREVIEW_CMD="$SVR_PREVIEW_CMD" \
timeout "$((RUNTIME_SEC + 10))s" bash "${SCRIPT_DIR}/run_server.sh" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

cleanup(){
  kill "$SERVER_PID" >/dev/null 2>&1 || true
  ssh_edge killall "$CLIENT_BIN_NAME" 2>/dev/null || true
}
trap cleanup EXIT

sleep 3
kill -0 "$SERVER_PID" 2>/dev/null || die "server failed to start — check $SERVER_LOG"
printf '[*] Server preview started (PID %d)\n' "$SERVER_PID"

ssh_edge killall "$CLIENT_BIN_NAME" 2>/dev/null || true
sleep 0.5
# client_uploader argv contract:
#   <server_ip> <primary_local_ip> [port] [backup_local_ip]
ssh_edge timeout "${RUNTIME_SEC}s" "${CLIENT_BIN}" "${SERVER_IP}" "${EDGE_WIFI_IP}" "${PORT}" "${EDGE_HOTSPOT_IP}" >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
printf '[*] Edge client started (PID %d) — %s\n' "$CLIENT_PID" "$CLIENT_BIN_NAME"

wait "$CLIENT_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
trap - EXIT

printf '\n[*] Preview run complete\n'
printf '[*] Server log: %s\n' "$SERVER_LOG"
printf '[*] Client log: %s\n' "$CLIENT_LOG"
