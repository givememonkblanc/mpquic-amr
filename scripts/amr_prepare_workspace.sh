#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
AMR_DIR="${AMR_DIR:-${ROOT_DIR}/amr}"

mkdir -p \
  "${AMR_DIR}/final_runs/handover" \
  "${AMR_DIR}/final_runs/degradation" \
  "${AMR_DIR}/final_runs/stream_aux" \
  "${AMR_DIR}/statistics/raw_qlogs" \
  "${AMR_DIR}/statistics/summary" \
  "${AMR_DIR}/docs" \
  "${AMR_DIR}/manifests"

ensure_file() {
  local file_path="$1"
  local header="$2"
  if [ ! -f "$file_path" ]; then
    printf '%s\n' "$header" > "$file_path"
  fi
}

ensure_file "${AMR_DIR}/manifests/final_runs.csv" \
  "scenario,run_id,source_dir,staged_dir,handshake_ready,camera_opened,frame_count,pqi_switch_count,has_preview,has_degradation_log,notes"
ensure_file "${AMR_DIR}/manifests/qlog_runs.csv" \
  "run_id,events_csv,snap_csv,frames,sent,bytes,switches,outage_events,outage_total_us,outage_avg_us"
ensure_file "${AMR_DIR}/manifests/statistics_summary.csv" \
  "claim_area,mode,run_count,mean_frames,mean_switches,mean_outage_us,summary_source,notes"

printf 'AMR workspace ready at %s\n' "${AMR_DIR}"
