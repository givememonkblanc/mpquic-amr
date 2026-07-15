#!/bin/bash
# run.sh — ONE command per drive, orchestrated from ryzen: it starts the ryzen
# server (with a per-run receiver qlog) AND the Orin client, then collects BOTH
# sides into a single run folder. No manual server/folder setup.
#
#   export SSHPASS='<orin password>'      # once per shell (Orin ssh)
#   ./run.sh start <rssi|pqi|default|spquic>
#   ./run.sh stop        # ends the run, pulls the Orin qlog, prints goodput/끊김
#   ./run.sh list        # per-run receiver-side summary
#
# One run folder gets: server_rx.csv (RECEIVER goodput/interruption ground truth),
# server.log, client/qlogs_client/*.csv (client send-side), client/client.log.
set -u
cd "$(dirname "$0")"
RUNS=${RUNS:-$PWD/runs}
SRV=${SRV:-/home/ryzen395/mpquic/build_d20/server_recv}
CERT=${CERT:-/home/ryzen395/mpquic/certs/cert.pem}
KEY=${KEY:-/home/ryzen395/mpquic/certs/key.pem}
PORT=${PORT:-4433}
SERVER_LAN=${SERVER_LAN:-192.168.0.38}; SERVER_PUB=${SERVER_PUB:-165.229.169.120}
PLOCAL=${PLOCAL:-192.168.0.13}; BLOCAL=${BLOCAL:-172.20.10.3}
ORIN_HOST=${ORIN_HOST:-100.109.159.8}; ORIN_USER=${ORIN_USER:-jetson}
ORIN_BASE=${ORIN_BASE:-/home/jetson/mpquic_refactor}
OCLIENT=$ORIN_BASE/build/client_uploader
STATE=/tmp/run_current
mkdir -p "$RUNS"
O(){ sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "$ORIN_USER@$ORIN_HOST" "$@"; }

srv_up(){ ss -ulnp 2>/dev/null | grep -q ":$PORT "; }

case "${1:-}" in
start)
  mode=${2:?"usage: ./run.sh start <rssi|pqi|default|spquic>"}
  [ -n "${SSHPASS:-}" ] || { echo "먼저: export SSHPASS='<orin 비번>'"; exit 1; }
  pgrep -x server_recv >/dev/null && { echo "❌ 서버 이미 실행중 — ./run.sh stop"; exit 1; }
  N=1; while [ -e "$RUNS/${mode}_$N" ]; do N=$((N+1)); done
  DIR="$RUNS/${mode}_$N"; mkdir -p "$DIR"
  echo "▶ [$mode #$N] → $DIR"
  # 1) ryzen server + per-run receiver qlog (folder already exists → no silent fail)
  MPQUIC_RX_QLOG="$DIR/server_rx.csv" setsid "$SRV" --port "$PORT" --cert "$CERT" --key "$KEY" \
    > "$DIR/server.log" 2>&1 < /dev/null & disown
  for i in $(seq 1 50); do srv_up && break; done
  srv_up && echo "  ✅ 서버 리슨 :$PORT (rx→$DIR/server_rx.csv)" || { echo "  ❌ 서버 안뜸"; tail -3 "$DIR/server.log"; exit 1; }
  # 2) Orin client, detached, into a per-run tmp on the Orin
  O "rm -rf /tmp/run_cli && mkdir -p /tmp/run_cli && cd /tmp/run_cli && setsid bash -c 'export MPQUIC_SCHED_MODE=$mode MPQUIC_SERVER_IP2=$SERVER_PUB MPQUIC_EXP_DURATION_US=1800000000; exec $OCLIENT $SERVER_LAN $PLOCAL $PORT $BLOCAL' > client.log 2>&1 < /dev/null & disown; echo ok" >/dev/null 2>&1
  echo "$mode $N $DIR" > "$STATE"
  for i in $(seq 1 14); do O "grep -q 'handshake complete' /tmp/run_cli/client.log 2>/dev/null" && break; sleep 1; done
  if O "grep -q 'handshake complete' /tmp/run_cli/client.log 2>/dev/null"; then
    echo "  ✅ 클라이언트 핸드셰이크 OK ($(O "grep -oE 'nb_paths=[0-9]+' /tmp/run_cli/client.log | tail -1"))"
    echo "  🚗 주행하세요.  끝나면: ./run.sh stop"
  else echo "  ⚠️ 클라이언트 핸드셰이크 미확인"; fi ;;
stop)
  [ -f "$STATE" ] || { echo "진행 중 없음"; exit 1; }
  read mode N DIR < "$STATE"
  echo "■ [$mode #$N] 정지..."
  O "pkill -INT -x client_uploader 2>/dev/null; sleep 3; pkill -9 -x client_uploader 2>/dev/null; echo done" >/dev/null 2>&1
  pkill -INT -x server_recv 2>/dev/null; sleep 2; pkill -9 -x server_recv 2>/dev/null
  rsync -a -e "sshpass -e ssh -o ConnectTimeout=12" "$ORIN_USER@$ORIN_HOST:/tmp/run_cli/" "$DIR/client/" 2>/dev/null
  rm -f "$STATE"
  echo "  → $DIR/  (server_rx.csv + server.log + client/)"
  echo "── 수신측 goodput/끊김 (ground truth) ──"
  python3 rx_analyze.py "$DIR/server_rx.csv" 2>/dev/null || echo "  (server_rx.csv 없음/빈값)" ;;
list)
  echo "runs in $RUNS:"
  for d in "$RUNS"/*/; do
    [ -f "$d/server_rx.csv" ] || continue
    printf "%-14s " "$(basename "$d")"
    python3 rx_analyze.py "$d/server_rx.csv" 2>/dev/null | grep -E 'goodput|끊김' | tr '\n' ' '; echo
  done ;;
*) echo "usage: ./run.sh {start <mode>|stop|list}   (export SSHPASS first)";;
esac
