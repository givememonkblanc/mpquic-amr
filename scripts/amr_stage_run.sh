#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/amr_stage_run.sh <scenario> <run_id> [source_dir] [dest_run_id] [notes]

Scenarios:
  handover | degradation | stream_aux

Examples:
  bash scripts/amr_stage_run.sh handover 20260617-record-handover-134544
  bash scripts/amr_stage_run.sh degradation 20260617-record-degrade-134426
EOF
}

[ "$#" -ge 2 ] || { usage >&2; exit 1; }

SCENARIO="$1"
RUN_ID="$2"

case "$SCENARIO" in
  handover|degradation|stream_aux) ;;
  *)
    printf '[!] invalid scenario: %s\n' "$SCENARIO" >&2
    exit 1
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
AMR_DIR="${AMR_DIR:-${ROOT_DIR}/amr}"
SRC_DIR="${3:-${ROOT_DIR}/experiment_runs/${RUN_ID}}"
DEST_RUN_ID="${4:-${RUN_ID}}"
NOTES="${5:-}"
DEST_DIR="${AMR_DIR}/final_runs/${SCENARIO}/${DEST_RUN_ID}"
MANIFEST="${AMR_DIR}/manifests/final_runs.csv"

bash "${SCRIPT_DIR}/amr_prepare_workspace.sh" >/dev/null

[ -d "$SRC_DIR" ] || { printf '[!] source run dir not found: %s\n' "$SRC_DIR" >&2; exit 1; }

rm -rf "$DEST_DIR"
mkdir -p "$DEST_DIR"
cp -a "$SRC_DIR/." "$DEST_DIR/"

EDGE_LOG="${DEST_DIR}/edge_client.log"
HANDSHAKE_READY="no"
CAMERA_OPENED="no"
PQI_SWITCH_COUNT="0"
FRAME_COUNT="0"
HAS_PREVIEW="no"
HAS_DEGRADATION_LOG="no"

if [ -f "$EDGE_LOG" ]; then
  if grep -q 'handshake complete' "$EDGE_LOG"; then
    HANDSHAKE_READY="yes"
  fi
  if grep -q '\[CAM\] real camera opened' "$EDGE_LOG"; then
    CAMERA_OPENED="yes"
  fi
  PQI_SWITCH_COUNT="$(grep -c '\[PQI_SWITCH\]' "$EDGE_LOG" || true)"
fi

if [ -d "${DEST_DIR}/frames" ]; then
  FRAME_COUNT="$(python3 - <<'PY' "$DEST_DIR/frames"
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
count = 0
for pattern in ('frame_*.jpg', 'frame_*.png'):
    count += len(list(root.glob(pattern)))
print(count)
PY
)"
fi

[ -f "${DEST_DIR}/preview.mp4" ] && HAS_PREVIEW="yes"
[ -f "${DEST_DIR}/degradation_ramp.log" ] && HAS_DEGRADATION_LOG="yes"

python3 - <<'PY' "$MANIFEST" "$SCENARIO" "$DEST_RUN_ID" "$SRC_DIR" "$DEST_DIR" "$HANDSHAKE_READY" "$CAMERA_OPENED" "$FRAME_COUNT" "$PQI_SWITCH_COUNT" "$HAS_PREVIEW" "$HAS_DEGRADATION_LOG" "$NOTES"
import csv
import pathlib
import sys

manifest = pathlib.Path(sys.argv[1])
row = {
    'scenario': sys.argv[2],
    'run_id': sys.argv[3],
    'source_dir': sys.argv[4],
    'staged_dir': sys.argv[5],
    'handshake_ready': sys.argv[6],
    'camera_opened': sys.argv[7],
    'frame_count': sys.argv[8],
    'pqi_switch_count': sys.argv[9],
    'has_preview': sys.argv[10],
    'has_degradation_log': sys.argv[11],
    'notes': sys.argv[12],
}
fields = list(row.keys())
rows = []
if manifest.exists():
    with manifest.open(newline='') as f:
        rows = list(csv.DictReader(f))

updated = False
for existing in rows:
    if existing['scenario'] == row['scenario'] and existing['run_id'] == row['run_id']:
        existing.update(row)
        updated = True
        break

if not updated:
    rows.append(row)

with manifest.open('w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
PY

printf 'Staged %s run %s -> %s\n' "$SCENARIO" "$RUN_ID" "$DEST_DIR"
