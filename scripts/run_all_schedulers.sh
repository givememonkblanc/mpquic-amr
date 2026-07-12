#!/usr/bin/env bash
#=============================================================================
# run_all_schedulers.sh — Automated Multi-Scheduler Experiment Runner
#=============================================================================
# Runs the MP-QUIC client across all 4 scheduler modes, collects QoS CSV logs,
# and prints summary statistics.
#
# Default behavior in this repository:
# - Start local server_recv on this host
# - Run client_uploader on the remote Jetson over SSH
# - Pull qlogs back from /home/jetson/qlogs_client into ./qlogs_client/
#=============================================================================

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env}"

SERVER_IP="${1:-192.168.0.80}"
PRIMARY_LOCAL="${2:-192.168.0.13}"
PORT="${3:-4433}"
BACKUP_LOCAL="${4:-172.20.10.3}"
DURATION_US="${5:-30000000}"

EDGE_PROJECT_DIR="${EDGE_PROJECT_DIR:-/home/jetson/client_multi_path_enhanced}"
CLIENT_BIN_NAME="${CLIENT_BIN_NAME:-client_uploader}"
CLIENT_BIN="${CLIENT_BIN:-${EDGE_PROJECT_DIR}/build_d20/${CLIENT_BIN_NAME}}"
REMOTE_QLOG_DIR="${REMOTE_QLOG_DIR:-/home/jetson/qlogs_client}"

RUN_ID="${RUN_ID:-$(date +%Y%m%d-scheduler-compare-%H%M%S)}"
RUN_DIR="${RUN_DIR:-${ROOT_DIR}/results/experiment_runs/${RUN_ID}}"
SERVER_LOG="${SERVER_LOG:-${RUN_DIR}/server.log}"
CLIENT_LOG_DIR="${CLIENT_LOG_DIR:-${RUN_DIR}/scheduler_logs}"
LOCAL_QLOG_DIR="${LOCAL_QLOG_DIR:-${ROOT_DIR}/results/qlogs_client}"

MODES=("pqi" "rssi" "default" "spquic")

die(){ printf '[!] %s\n' "$*" >&2; exit 1; }

[ -f "$ENV_FILE" ] || die "env file not found: $ENV_FILE"
mkdir -p "$RUN_DIR" "$CLIENT_LOG_DIR" "$LOCAL_QLOG_DIR"

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

cleanup(){
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    ssh_edge killall "$CLIENT_BIN_NAME" 2>/dev/null || true
}
trap cleanup EXIT

TUNE_RP_FILTER=0 OUT_DIR="${RUN_DIR}/frames" timeout "$((DURATION_US / 1000000 + 20))s" bash "${SCRIPT_DIR}/run_server.sh" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 3
kill -0 "$SERVER_PID" 2>/dev/null || die "server failed to start — check $SERVER_LOG"

printf '============================================\n'
printf ' Scheduler Comparison Experiment\n'
printf '============================================\n'
printf ' Server:       %s:%s\n' "$SERVER_IP" "$PORT"
printf ' Primary IP:   %s\n' "$PRIMARY_LOCAL"
printf ' Backup IP:    %s\n' "$BACKUP_LOCAL"
printf ' Duration:     %s s\n' "$((DURATION_US / 1000000))"
printf ' Modes:        %s\n' "${MODES[*]}"
printf ' Remote edge:  %s@%s\n' "$SSH_ID" "$SSH_ADDRESS"
printf ' Local qlogs:  %s\n' "$LOCAL_QLOG_DIR"
printf '============================================\n\n'

ssh_edge mkdir -p "$REMOTE_QLOG_DIR"

for mode in "${MODES[@]}"; do
    printf '%s\n' '----------------------------------------'
    printf '  Running mode: %s\n' "$mode"
    printf '%s\n' '----------------------------------------'

    MODE_CLIENT_LOG="${CLIENT_LOG_DIR}/${mode}.log"
    START_WALL=$(date +%s%6N)

    ssh_edge killall "$CLIENT_BIN_NAME" 2>/dev/null || true

    ssh_edge rm -f "${REMOTE_QLOG_DIR}/${mode}_${SERVER_IP}_events.csv" "${REMOTE_QLOG_DIR}/${mode}_${SERVER_IP}_snap.csv" 2>/dev/null || true

    if ! sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/opencode/known_hosts "${SSH_ID}@${SSH_ADDRESS}" \
        "cd /home/jetson && MPQUIC_SCHED_MODE='${mode}' MPQUIC_EXP_DURATION_US='${DURATION_US}' timeout '$((DURATION_US / 1000000 + 5))s' '${CLIENT_BIN}' '${SERVER_IP}' '${PRIMARY_LOCAL}' '${PORT}' '${BACKUP_LOCAL}'" >"$MODE_CLIENT_LOG" 2>&1; then
        printf '  [WARN] client exited non-zero for mode=%s\n' "$mode"
    fi

    END_WALL=$(date +%s%6N)
    ELAPSED_MS=$(( (END_WALL - START_WALL) / 1000 ))
    printf '  Elapsed: %sms\n\n' "$ELAPSED_MS"

    sshpass -p "$SSH_PASSWORD" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/opencode/known_hosts "${SSH_ID}@${SSH_ADDRESS}:${REMOTE_QLOG_DIR}/${mode}_${SERVER_IP}_events.csv" "$LOCAL_QLOG_DIR/" >/dev/null 2>&1 || true
    sshpass -p "$SSH_PASSWORD" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/opencode/known_hosts "${SSH_ID}@${SSH_ADDRESS}:${REMOTE_QLOG_DIR}/${mode}_${SERVER_IP}_snap.csv" "$LOCAL_QLOG_DIR/" >/dev/null 2>&1 || true

    sleep 2
done

printf '\n============================================\n'
printf '  Summary (from CSV logs)\n'
printf '============================================\n'

for mode in "${MODES[@]}"; do
    EVENTS_FILE="${LOCAL_QLOG_DIR}/${mode}_${SERVER_IP}_events.csv"
    if [[ ! -f "$EVENTS_FILE" ]]; then
        printf '  %s: no CSV log found\n' "$mode"
        continue
    fi
    SUMMARY=$(grep '^# SUMMARY' "$EVENTS_FILE" 2>/dev/null || echo 'no summary')
    printf '  %s: %s\n' "$mode" "$SUMMARY"
done

printf '\n============================================\n'
printf '  Done. CSV logs in %s\n' "$LOCAL_QLOG_DIR/"
printf '============================================\n'
