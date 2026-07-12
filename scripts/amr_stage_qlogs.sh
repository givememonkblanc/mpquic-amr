#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/amr_stage_qlogs.sh <run-prefix-or-run-id> [more-prefixes...]

Examples:
  bash scripts/amr_stage_qlogs.sh pqi default rssi spquic
  bash scripts/amr_stage_qlogs.sh 20260619-foo-run 20260619-bar-run
EOF
}

[ "$#" -ge 1 ] || { usage >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
AMR_DIR="${AMR_DIR:-${ROOT_DIR}/amr}"
QLOG_SRC_DIR="${QLOG_SRC_DIR:-${ROOT_DIR}/results/qlogs_client}"
DEST_DIR="${AMR_DIR}/statistics/raw_qlogs"
MANIFEST="${AMR_DIR}/manifests/qlog_runs.csv"

bash "${SCRIPT_DIR}/amr_prepare_workspace.sh" >/dev/null

[ -d "$QLOG_SRC_DIR" ] || { printf '[!] qlog source dir not found: %s\n' "$QLOG_SRC_DIR" >&2; exit 1; }

for prefix in "$@"; do
  matched=0
  for events_file in "$QLOG_SRC_DIR"/"${prefix}"*_events.csv; do
    [ -e "$events_file" ] || continue
    matched=1
    base_name="$(basename "$events_file")"
    run_id="${base_name%_events.csv}"
    snap_file="$QLOG_SRC_DIR/${run_id}_snap.csv"

    cp -a "$events_file" "$DEST_DIR/"
    [ -f "$snap_file" ] && cp -a "$snap_file" "$DEST_DIR/"

    python3 - <<'PY' "$MANIFEST" "$run_id" "$DEST_DIR/${run_id}_events.csv" "$DEST_DIR/${run_id}_snap.csv"
import csv
import pathlib
import re
import sys

manifest = pathlib.Path(sys.argv[1])
run_id = sys.argv[2]
events_csv = pathlib.Path(sys.argv[3])
snap_csv = pathlib.Path(sys.argv[4])

summary = {
    'run_id': run_id,
    'events_csv': str(events_csv),
    'snap_csv': str(snap_csv if snap_csv.exists() else ''),
    'frames': '',
    'sent': '',
    'bytes': '',
    'switches': '',
    'outage_events': '',
    'outage_total_us': '',
    'outage_avg_us': '',
}

summary_re = re.compile(
    r'^# SUMMARY: frames=(\d+) sent=(\d+) bytes=(\d+) switches=(\d+) '
    r'outage_events=(\d+) outage_total_us=(\d+) outage_avg_us=([0-9.]+)$'
)

with events_csv.open() as f:
    for line in f:
        line = line.strip()
        match = summary_re.match(line)
        if match:
            summary['frames'] = match.group(1)
            summary['sent'] = match.group(2)
            summary['bytes'] = match.group(3)
            summary['switches'] = match.group(4)
            summary['outage_events'] = match.group(5)
            summary['outage_total_us'] = match.group(6)
            summary['outage_avg_us'] = match.group(7)
            break

fields = list(summary.keys())
rows = []
if manifest.exists():
    with manifest.open(newline='') as f:
        rows = list(csv.DictReader(f))

updated = False
for existing in rows:
    if existing['run_id'] == run_id:
        existing.update(summary)
        updated = True
        break

if not updated:
    rows.append(summary)

with manifest.open('w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
PY
    printf 'Staged qlogs for %s\n' "$run_id"
  done

  if [ "$matched" -eq 0 ]; then
    printf '[!] no qlog matches for prefix: %s\n' "$prefix" >&2
  fi
done
