# AMR Readiness Validation

Status: **NOT READY TO RAISE AMR YET**

This file evaluates the current repository state against the AMR pre-submission checklist using only repository evidence.

## Summary judgment

The repository shows that the experiment pipeline is largely implemented and recent runs exist. An AMR staging workspace now exists, but the final evidence chain is still incomplete.

Primary blockers:

1. The documented final valid run IDs in `validated_localip_results.md` are not present under `experiment_runs/`.
2. The repeated-experiment/statistical reporting path exists in code, but the expected `qlogs_client` CSV artifacts are not present.
3. Candidate AMR runs are now staged under `amr/final_runs/`, but the documented final run IDs still do not match the preserved canonical set.

## Checklist evaluation

### 1. Environment readiness

| Item | Status | Evidence |
|---|---|---|
| `.env` exists | PASS | `.env` exists at repo root |
| Jetson SSH-based workflow configured | PASS | `scripts/run_handover_experiment.sh`, `scripts/run_degradation_experiment.sh` parse SSH credentials from `.env` |
| Dual-path assumptions encoded | PASS | Wi-Fi and hotspot variables are hard-coded in both experiment scripts |
| Validated local server IP set to `192.168.0.80` | PASS | `validated_localip_results.md:21`, `scripts/run_handover_experiment.sh:18`, `scripts/run_degradation_experiment.sh:20` |
| Source-policy routing support exists | PASS | `scripts/route_setup.sh`, in-script `setup_policy_routing()` |

### 2. Build readiness

| Item | Status | Evidence |
|---|---|---|
| `build/server_recv` exists | PASS | `build/server_recv` present |
| `build/client_uploader` exists | PASS | `build/client_uploader` present |
| Build script exists | PASS | `scripts/build.sh` |
| OpenCV requirement can still be a deployment risk | WARN | `CMakeLists.txt:114` warns that `client_uploader` is skipped if OpenCV is missing |

### 3. Functional run validation

| Item | Status | Evidence |
|---|---|---|
| Real camera open verified | PASS | `experiment_runs/20260617-record-handover-134544/edge_client.log:5-6`, `experiment_runs/20260617-record-degrade-134426/edge_client.log:5-6` |
| Handshake ready verified | PASS | `experiment_runs/20260617-record-handover-134544/edge_client.log:15-16`, `experiment_runs/20260617-record-degrade-134426/edge_client.log:15-16` |
| Both paths observed | PASS | `EXP_PATH_STATE` shows `192.168.0.13` and `172.20.10.3` in both recent runs |
| Scheduler switching observed | PASS | many `[PQI_SWITCH]` entries across recent `edge_client.log` files |
| Degradation ramp executed | PASS | `experiment_runs/20260617-record-degrade-134426/degradation_ramp.log:11-19` |
| Handover/disconnect-reconnect script exists and recent handover run exists | PASS | `scripts/run_handover_experiment.sh`, `experiment_runs/20260617-record-handover-134544/` |

### 4. Artifact completeness

| Item | Status | Evidence |
|---|---|---|
| Recent handover artifact directory preserved | PASS | `experiment_runs/20260617-record-handover-134544/` has `edge_client.log`, `server.log`, `frames/`, `preview.mp4`; staged to `amr/final_runs/handover/20260617-record-handover-134544/` |
| Recent degradation artifact directory preserved | PASS | `experiment_runs/20260617-record-degrade-134426/` has `edge_client.log`, `server.log`, `frames/`, `preview.mp4`, `degradation_ramp.log`; staged to `amr/final_runs/degradation/20260617-record-degrade-134426/` |
| Recent stream artifact exists | PARTIAL | `experiment_runs/20260617-record-stream-134334/` has logs and `preview.mp4`, but no `frames/` directory |
| Final documented run IDs preserved | FAIL | `validated_localip_results.md` references `20260617-camera-strict-handover-localip-2` and `20260617-camera-strict-degrade-localip-2`, but those run directories are not present under `experiment_runs/` |

### 5. Statistical evidence

| Item | Status | Evidence |
|---|---|---|
| Qlogger code path implemented | PASS | `client/client_qlogger.h`, `client/client_qlogger.c` |
| Batch runner for all schedulers exists | PASS | `scripts/run_all_schedulers.sh` |
| `qlogs_client/*_events.csv` present now | FAIL | no `qlogs_client/` directory found in repo root |
| `# SUMMARY` lines preserved in CSV artifacts | FAIL | no matching events CSV artifacts found |
| Repeated-run aggregated statistics document present | FAIL | no repo evidence of final mean/variance/statistical summary table |

### 6. Documentation consistency

| Item | Status | Evidence |
|---|---|---|
| Valid local-IP result note exists | PASS | `validated_localip_results.md` |
| Invalid public-IP runs explicitly rejected | PASS | `validated_localip_results.md:20-21` |
| Documented run IDs map to preserved artifacts | FAIL | mismatch between markdown run IDs and preserved `experiment_runs/` directories |
| Submission-ready final run set explicitly identified | PARTIAL | `amr/docs/final_run_set.md` now stages candidate canonical runs, but `validated_localip_results.md` still points at different run IDs |

## Recommended actions before AMR

### Must do

1. Preserve the actual final valid handover/degradation run directories under the exact run IDs referenced in `validated_localip_results.md`, or update the markdown to reference the staged directories that actually exist under `amr/final_runs/`.
2. Run the repeated scheduler/statistics flow and preserve:
   - `qlogs_client/*_events.csv`
   - `qlogs_client/*_snap.csv`
   - derived summary table
3. Promote the staged AMR candidate run set to the canonical final run set and use those exact names everywhere.

### Should do

1. Add a small markdown table summarizing the final preserved runs:
   - scenario
   - run ID
   - frames
   - handshake status
   - camera status
   - switch count
   - artifact path
2. Keep one note explaining why older public-IP runs were invalidated.
3. Confirm whether stream-only recorded runs are part of AMR scope or just auxiliary evidence.

## Bottom line

The code and recent logs suggest the system is close, but **AMR should wait until the final documented run IDs and the statistical artifacts are aligned and preserved**.
