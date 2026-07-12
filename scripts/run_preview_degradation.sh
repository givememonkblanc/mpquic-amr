#!/usr/bin/env bash
# run_preview_degradation.sh — degradation experiment with live preview and no frame accumulation by default
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

SVR_PREVIEW="${SVR_PREVIEW:-1}"
SVR_SAVE_FRAMES="${SVR_SAVE_FRAMES:-0}"
SERVER_IP="${SERVER_IP:-192.168.0.80}"
# Preview degradation also depends on source-policy routing for Wi‑Fi/backup path separation.
# Override to 1 only when the edge already has the required policy rules installed.
SKIP_EDGE_ROUTE_SETUP="${SKIP_EDGE_ROUTE_SETUP:-0}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-preview-degrade-%H%M%S)}"

exec env \
  SVR_PREVIEW="$SVR_PREVIEW" \
  SVR_SAVE_FRAMES="$SVR_SAVE_FRAMES" \
  SERVER_IP="$SERVER_IP" \
  SKIP_EDGE_ROUTE_SETUP="$SKIP_EDGE_ROUTE_SETUP" \
  RUN_ID="$RUN_ID" \
  bash "${SCRIPT_DIR}/run_degradation_experiment.sh"
