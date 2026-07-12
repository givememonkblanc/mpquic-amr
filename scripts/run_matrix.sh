#!/usr/bin/env bash
#=============================================================================
# run_matrix.sh — reviewer-response experiment matrix
#=============================================================================
# Runs {scenario} × {scheduler mode} × N repetitions and collects per-run
# server logs + client logs + client QoS CSVs (qlogs) for the statistics
# pipeline. Feeds the revised paper's Table 2 and Figs. 5–9.
#
#   scenarios : steady       — no impairment (Table 2 normal state, R3.9)
#               handover     — Wi-Fi disconnect → reconnect (Figs 5/6/8/9, R2.10)
#               degradation  — iptables loss ramp + optional iperf3 cross
#                              traffic (Fig 7, R2.7, R3.7 proactive evidence)
#   modes     : rssi pqi default spquic   (R1.10 / R3.4 same-stack baselines)
#
# Usage:
#   REPS=10 bash scripts/run_matrix.sh                 # full matrix
#   REPS=1 SCENARIOS="steady" MODES="rssi" bash ...    # smoke test
#
# Every run continues on failure (marked FAILED) so an unattended overnight
# matrix never dies half-way.
#=============================================================================
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${SCRIPT_DIR}/exp_env.sh"

REPS="${REPS:-10}"
MODES=(${MODES:-rssi pqi default spquic})
SCENARIOS=(${SCENARIOS:-steady handover degradation})
STEADY_SEC="${STEADY_SEC:-30}"
HANDOVER_RUNTIME_SEC="${HANDOVER_RUNTIME_SEC:-40}"
HANDOVER_AT_SEC="${HANDOVER_AT_SEC:-10}"
FAILBACK_AFTER_SEC="${FAILBACK_AFTER_SEC:-10}"
DEGRADATION_RUNTIME_SEC="${DEGRADATION_RUNTIME_SEC:-50}"
PAUSE_BETWEEN_RUNS_SEC="${PAUSE_BETWEEN_RUNS_SEC:-8}"

MATRIX_ID="${MATRIX_ID:-$(date +%Y%m%d-matrix-%H%M%S)}"
MATRIX_DIR="${ROOT_DIR}/results/experiment_runs/${MATRIX_ID}"
mkdir -p "$MATRIX_DIR"
SUMMARY="${MATRIX_DIR}/matrix_summary.tsv"
echo -e "scenario\tmode\trep\tstatus\tframes_rx\tnotes" > "$SUMMARY"

# ── ssh helper (same .env parsing the other scripts use) ──
ENV_FILE="${ROOT_DIR}/.env"
# SSH_ADDRESS comes from exp_env.sh (Tailscale) — parse only id/password here.
SSH_ID="$(python3 -c "
import pathlib,re,sys
t=pathlib.Path(sys.argv[1]).read_text()
print({m.group(1):m.group(2) for m in re.finditer(r'^(ssh_address|ssh_id|ssh_password)\s*=\s*[\x27\"]([^\x27\"]+)[\x27\"]\s*$',t,re.M)}['ssh_id'])" "$ENV_FILE")"
SSH_PASSWORD="$(python3 -c "
import pathlib,re,sys
t=pathlib.Path(sys.argv[1]).read_text()
print({m.group(1):m.group(2) for m in re.finditer(r'^(ssh_address|ssh_id|ssh_password)\s*=\s*[\x27\"]([^\x27\"]+)[\x27\"]\s*$',t,re.M)}['ssh_password'])" "$ENV_FILE")"
# Experiments must survive Wi-Fi disconnection on the edge → always ssh via
# Tailscale, never via the Wi-Fi IP.
ssh_edge(){ sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "${SSH_ID}@${SSH_ADDRESS}" "$@"; }

log(){ printf '[matrix %s] %s\n' "$(date +%H:%M:%S)" "$*"; }

# ── environment reset between runs ──
reset_stack(){
  pkill -x server_recv 2>/dev/null || true
  ssh_edge "tmux kill-session -t cam 2>/dev/null; killall ${CLIENT_BIN_NAME} iperf3 2>/dev/null;
            echo '${SSH_PASSWORD}' | sudo -S iptables -F OUTPUT 2>/dev/null;
            echo '${SSH_PASSWORD}' | sudo -S nmcli device connect ${EDGE_WIFI_IFACE} >/dev/null 2>&1;
            rm -f ${REMOTE_QLOG_DIR}/*.csv; true" >/dev/null 2>&1 || true
  sleep 2
  # wait until Wi-Fi IP is back (max 30 s)
  for _ in $(seq 1 15); do
    if ssh_edge "ip -4 addr show ${EDGE_WIFI_IFACE} | grep -q 'inet ${EDGE_WIFI_IP}'"; then return 0; fi
    ssh_edge "echo '${SSH_PASSWORD}' | sudo -S nmcli con up '${EDGE_WIFI_CON_NAME}' >/dev/null 2>&1; true" || true
    sleep 2
  done
  log "WARN: Wi-Fi IP not confirmed after reset"
}

collect_qlogs(){ # $1 = run dir
  mkdir -p "$1/qlogs"
  sshpass -p "$SSH_PASSWORD" scp -o StrictHostKeyChecking=no \
    "${SSH_ID}@${SSH_ADDRESS}:${REMOTE_QLOG_DIR}/*.csv" "$1/qlogs/" 2>/dev/null || true
  ssh_edge "rm -f ${REMOTE_QLOG_DIR}/*.csv; true" 2>/dev/null || true
}

count_frames(){ # $1 = server log
  grep -ac '\[FA\] frame' "$1" 2>/dev/null || echo 0
}

run_steady(){ # $1 mode  $2 run dir
  local mode="$1" rd="$2"
  mkdir -p "$rd/frames"
  TUNE_RP_FILTER=0 SVR_SAVE_FRAMES=0 OUT_DIR="$rd/frames" BUILD_DIR="$BUILD_DIR" \
    timeout "$((STEADY_SEC + 20))s" bash "${SCRIPT_DIR}/run_server.sh" >"$rd/server.log" 2>&1 &
  local spid=$!
  sleep 3
  ssh_edge env "MPQUIC_SCHED_MODE=${mode}" "MPQUIC_EXP_DURATION_US=$((STEADY_SEC * 1000000))" \
    "MPQUIC_NO_RECONNECT=1" timeout "$((STEADY_SEC + 5))s" \
    "$CLIENT_BIN" "$SERVER_IP" "$EDGE_WIFI_IP" "$PORT" "$EDGE_HOTSPOT_IP" \
    >"$rd/edge_client.log" 2>&1 || true
  kill "$spid" 2>/dev/null || true
  wait "$spid" 2>/dev/null || true
}

run_one(){ # $1 scenario  $2 mode  $3 rep
  local scenario="$1" mode="$2" rep="$3"
  local rd="${MATRIX_DIR}/${scenario}_${mode}_rep${rep}"
  mkdir -p "$rd"
  log "── ${scenario} / ${mode} / rep ${rep} ──"
  reset_stack

  local status="OK" notes=""
  case "$scenario" in
    steady)
      run_steady "$mode" "$rd" || status="FAILED" ;;
    handover)
      MPQUIC_SCHED_MODE="$mode" RUN_DIR="$rd" RUNTIME_SEC="$HANDOVER_RUNTIME_SEC" \
      HANDOVER_AT_SEC="$HANDOVER_AT_SEC" FAILBACK_AFTER_SEC="$FAILBACK_AFTER_SEC" \
      SVR_SAVE_FRAMES=0 SKIP_EDGE_ROUTE_SETUP="$SKIP_EDGE_ROUTE_SETUP" \
      bash "${SCRIPT_DIR}/run_handover_experiment.sh" >"$rd/driver.log" 2>&1 || status="FAILED" ;;
    degradation)
      MPQUIC_SCHED_MODE="$mode" RUN_DIR="$rd" RUNTIME_SEC="$DEGRADATION_RUNTIME_SEC" \
      SVR_SAVE_FRAMES=0 SKIP_EDGE_ROUTE_SETUP="$SKIP_EDGE_ROUTE_SETUP" \
      bash "${SCRIPT_DIR}/run_degradation_experiment.sh" >"$rd/driver.log" 2>&1 || status="FAILED" ;;
    *) status="FAILED"; notes="unknown scenario" ;;
  esac

  collect_qlogs "$rd"
  local frames; frames="$(count_frames "$rd/server.log")"
  [ "$frames" -eq 0 ] && [ "$status" = "OK" ] && { status="EMPTY"; notes="no frames at server"; }
  echo -e "${scenario}\t${mode}\t${rep}\t${status}\t${frames}\t${notes}" >> "$SUMMARY"
  log "   → ${status} (frames_rx=${frames})"
  sleep "$PAUSE_BETWEEN_RUNS_SEC"
}

log "matrix ${MATRIX_ID}: scenarios=[${SCENARIOS[*]}] modes=[${MODES[*]}] reps=${REPS}"
log "results → ${MATRIX_DIR}"

for rep in $(seq 1 "$REPS"); do
  for scenario in "${SCENARIOS[@]}"; do
    for mode in "${MODES[@]}"; do
      run_one "$scenario" "$mode" "$rep"
    done
  done
done

reset_stack
log "matrix complete"
column -t "$SUMMARY" | tail -n +1
