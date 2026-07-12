#!/usr/bin/env bash
# run_server.sh — robust launcher for server_recv
set -Eeuo pipefail

# ========== Paths (safe defaults) ==========
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build_d20}"
CERT_DIR="${CERT_DIR:-${ROOT_DIR}/certs}"

BIN="${BIN:-${BUILD_DIR}/server_recv}"
PORT="${PORT:-4433}"
CERT="${CERT:-${CERT_DIR}/cert.pem}"
KEY="${KEY:-${CERT_DIR}/key.pem}"
QLOG_DIR="${QLOG_DIR:-${BUILD_DIR}/qlogs_svr}"
BINLOG_DIR="${BINLOG_DIR:-${BUILD_DIR}/binlog_svr}"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/results/frames_out}"
SVR_PREVIEW="${SVR_PREVIEW:-0}"
SVR_SAVE_FRAMES="${SVR_SAVE_FRAMES:-1}"
SVR_PREVIEW_CMD="${SVR_PREVIEW_CMD:-}"

TUNE_RP_FILTER="${TUNE_RP_FILTER:-1}"
IFACES=(${IFACES:-eth0 wlan0})

die(){ echo "[!] $*" >&2; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }

# ========== Checks ==========
[ -x "$BIN" ] || die "not executable: $BIN (먼저 빌드하세요: bash ${SCRIPT_DIR}/build.sh)"

mkdir -p "$QLOG_DIR" "$BINLOG_DIR" "$CERT_DIR" "$OUT_DIR"

# cert/key 없으면 생성
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  echo "[*] cert/key not found → generating self-signed (CN=localhost)"
  have openssl || die "openssl 필요"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY" -out "$CERT" -subj "/CN=localhost" -days 365 >/dev/null 2>&1
fi

# rp_filter 완화
if [ "$TUNE_RP_FILTER" = "1" ]; then
  echo "[*] relax rp_filter"
  sudo sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null
  for i in "${IFACES[@]}"; do
    sudo sysctl -w "net.ipv4.conf.${i}.rp_filter=2" >/dev/null || true
  done
fi

ulimit -n 65535 || true

# 빌드 디렉토리에서 실행 + cert/key 링크 정리
ln -sf "$CERT" "$BUILD_DIR/cert.pem"
ln -sf "$KEY"  "$BUILD_DIR/key.pem"
cd "$BUILD_DIR"

echo "[*] launching: $BIN"
echo "    PORT=$PORT"
echo "    CERT=$CERT"
echo "    KEY =$KEY"
echo "    OUT_DIR=$OUT_DIR"
echo "    QLOG_DIR=$QLOG_DIR  BINLOG_DIR=$BINLOG_DIR"
echo "    SVR_PREVIEW=$SVR_PREVIEW  SVR_SAVE_FRAMES=$SVR_SAVE_FRAMES"
if [ -n "$SVR_PREVIEW_CMD" ]; then
  echo "    SVR_PREVIEW_CMD=$SVR_PREVIEW_CMD"
fi

exec ./server_recv --port "$PORT" --cert "$CERT" --key "$KEY" --out "$OUT_DIR" --qlog --binlog
