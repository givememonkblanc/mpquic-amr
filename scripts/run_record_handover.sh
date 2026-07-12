#!/usr/bin/env bash
# run_record_handover.sh — handover experiment recorded to a playable video file
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-record-handover-%H%M%S)}"
RUN_DIR="${RUN_DIR:-${ROOT_DIR}/results/experiment_runs/${RUN_ID}}"
VIDEO_FILE="${VIDEO_FILE:-${RUN_DIR}/preview.mp4}"

mkdir -p "$RUN_DIR"

SVR_PREVIEW_CMD_DEFAULT="ffmpeg -y -loglevel error -fflags nobuffer -framerate 30 -f mjpeg -i - -an -c:v libx264 -preset veryfast -tune zerolatency -profile:v high -b:v 2M -maxrate 4M -bufsize 4M -bf 0 -pix_fmt yuv420p \"${VIDEO_FILE}\""

exec env \
  RUN_ID="$RUN_ID" \
  RUN_DIR="$RUN_DIR" \
  SVR_PREVIEW=1 \
  SVR_SAVE_FRAMES="${SVR_SAVE_FRAMES:-0}" \
  SVR_PREVIEW_CMD="${SVR_PREVIEW_CMD:-$SVR_PREVIEW_CMD_DEFAULT}" \
  bash "${SCRIPT_DIR}/run_preview_handover.sh"
