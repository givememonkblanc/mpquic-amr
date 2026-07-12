#!/usr/bin/env bash
set -Eeuo pipefail
SERVER_IP=${SERVER_IP:-192.168.0.38}         # 서버 IP
PRIMARY_LOCAL_IP=${PRIMARY_LOCAL_IP:-192.168.0.13}  # 선호 로컬 경로 (예: Wi‑Fi)
BACKUP_LOCAL_IP=${BACKUP_LOCAL_IP:-172.20.10.3}     # 백업 로컬 경로 (예: USB tether)
PORT=${PORT:-4433}
./build_d20/client_uploader "$SERVER_IP" "$PRIMARY_LOCAL_IP" "$PORT" "$BACKUP_LOCAL_IP"
