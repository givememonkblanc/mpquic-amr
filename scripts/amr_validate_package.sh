#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
AMR_DIR="${AMR_DIR:-${ROOT_DIR}/amr}"

bash "${SCRIPT_DIR}/amr_prepare_workspace.sh" >/dev/null

python3 - <<'PY' "$ROOT_DIR" "$AMR_DIR"
import csv
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
amr = pathlib.Path(sys.argv[2])

failures = []
warnings = []
passes = []

def ok(msg):
    passes.append(msg)

def warn(msg):
    warnings.append(msg)

def fail(msg):
    failures.append(msg)

required_docs = [
    root / 'amr_pre_submission_checklist.md',
    root / 'amr_readiness_validation.md',
    amr / 'README.md',
    amr / 'docs' / 'final_run_set.md',
    amr / 'docs' / 'final_submission_notes.md',
]
for doc in required_docs:
    if doc.exists():
        ok(f'doc present: {doc.relative_to(root)}')
    else:
        fail(f'missing doc: {doc.relative_to(root)}')

final_manifest = amr / 'manifests' / 'final_runs.csv'
qlog_manifest = amr / 'manifests' / 'qlog_runs.csv'
stats_manifest = amr / 'manifests' / 'statistics_summary.csv'

for manifest in [final_manifest, qlog_manifest, stats_manifest]:
    if manifest.exists():
        ok(f'manifest present: {manifest.relative_to(root)}')
    else:
        fail(f'missing manifest: {manifest.relative_to(root)}')

if final_manifest.exists():
    with final_manifest.open(newline='') as f:
        rows = list(csv.DictReader(f))
    if not rows:
        warn('no staged final runs recorded in amr/manifests/final_runs.csv')
    for row in rows:
        scenario = row['scenario']
        run_id = row['run_id']
        staged_dir = pathlib.Path(row['staged_dir'])
        if not staged_dir.exists():
            fail(f'staged dir missing for {scenario}/{run_id}: {staged_dir}')
            continue
        if not (staged_dir / 'edge_client.log').exists():
            fail(f'edge_client.log missing for {scenario}/{run_id}')
        if not (staged_dir / 'server.log').exists():
            fail(f'server.log missing for {scenario}/{run_id}')
        if scenario == 'degradation' and not (staged_dir / 'degradation_ramp.log').exists():
            fail(f'degradation_ramp.log missing for degradation/{run_id}')
        if row['handshake_ready'] != 'yes':
            warn(f'handshake not marked ready for {scenario}/{run_id}')
        if row['camera_opened'] != 'yes':
            warn(f'camera not marked open for {scenario}/{run_id}')
        ok(f'final run staged: {scenario}/{run_id}')

if qlog_manifest.exists():
    with qlog_manifest.open(newline='') as f:
        rows = list(csv.DictReader(f))
    if not rows:
        warn('no staged qlog runs recorded in amr/manifests/qlog_runs.csv')
    for row in rows:
        run_id = row['run_id']
        events_csv = pathlib.Path(row['events_csv']) if row['events_csv'] else None
        snap_csv = pathlib.Path(row['snap_csv']) if row['snap_csv'] else None
        if not events_csv or not events_csv.exists():
            fail(f'events csv missing for qlog run {run_id}')
        else:
            ok(f'qlog events present: {run_id}')
        if snap_csv and str(snap_csv) and not snap_csv.exists():
            fail(f'snap csv missing for qlog run {run_id}')
        if not row['frames']:
            warn(f'no parsed # SUMMARY line for qlog run {run_id}')

validated_doc = root / 'validated_localip_results.md'
if validated_doc.exists():
    text = validated_doc.read_text()
    import re
    run_ids = re.findall(r'`(20\d{6,}[^`]*)`', text)
    for run_id in run_ids:
        found = False
        if (root / 'experiment_runs' / run_id).exists():
            found = True
        for scenario_dir in (amr / 'final_runs').glob('*'):
            if scenario_dir.is_dir() and (scenario_dir / run_id).exists():
                found = True
                break
        if found:
            ok(f'validated run id preserved: {run_id}')
        else:
            warn(f'validated run id not yet preserved: {run_id}')

print('AMR package validation')
print('======================')
for msg in passes:
    print(f'PASS: {msg}')
for msg in warnings:
    print(f'WARN: {msg}')
for msg in failures:
    print(f'FAIL: {msg}')

if failures:
    sys.exit(1)
PY
