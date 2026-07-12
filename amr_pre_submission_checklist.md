# AMR Pre-Submission Checklist

Use this checklist immediately before raising AMR. AMR is treated as the final step, so every item below should be checked with concrete evidence.

## 1. Environment readiness

- [ ] `.env` exists and contains working SSH credentials for the Jetson edge device.
- [ ] Jetson edge device is reachable over SSH.
- [ ] Both client paths are available at run time:
  - [ ] Wi-Fi path (`EDGE_WIFI_IFACE`, default `wlP1p1s0`)
  - [ ] USB hotspot path (`EDGE_HOTSPOT_IP`, default `172.20.10.3`)
- [ ] Server IP is the validated local address `192.168.0.80`.
- [ ] Source-policy routing is installed for the Wi-Fi source IP.
- [ ] Any optional wired interface disable/enable behavior is understood before the run.

Reference:
- `scripts/run_handover_experiment.sh`
- `scripts/run_degradation_experiment.sh`
- `scripts/route_setup.sh`
- `validated_localip_results.md`

## 2. Build readiness

- [ ] `build/server_recv` exists and is executable.
- [ ] `build/client_uploader` exists and is executable.
- [ ] Certificates can be generated or are already present.
- [ ] OpenCV is installed so `client_uploader` is actually built.

Reference:
- `scripts/build.sh`
- `scripts/run_server.sh`
- `CMakeLists.txt`

## 3. Functional run validation

For the final run set, verify all of the following in the logs.

- [ ] Real camera is used (`[CAM] using /dev/video0` / `[CAM] real camera opened`).
- [ ] Handshake completes successfully (`handshake complete → ready`).
- [ ] Both paths become visible and verified in path-state logs.
- [ ] Scheduler switch events are present when expected.
- [ ] Handover scenario shows disconnect/reconnect behavior and recovery.
- [ ] Degradation scenario shows packet-loss ramp behavior and recovery.

Reference signals:
- `edge_client.log`: `[CAM]`, `[EXP_HANDSHAKE]`, `[EXP_PATH_STATE]`, `[PQI_SWITCH]`
- `degradation_ramp.log`: ramp step completion lines

## 4. Artifact completeness

For each final submission run, keep one self-contained artifact directory.

- [ ] `server.log`
- [ ] `edge_client.log`
- [ ] `frames/` directory when frame saving is required
- [ ] `preview.mp4` when recorded preview is required
- [ ] `degradation_ramp.log` for degradation runs
- [ ] Run directory name is stable and referenced consistently in documents

Expected location:
- `experiment_runs/<run-id>/`

## 5. Statistical evidence

If AMR claims repeated experiments or quantitative comparison, these are mandatory.

- [ ] `qlogs_client/*_events.csv` exists for the claimed runs.
- [ ] `qlogs_client/*_snap.csv` exists for the claimed runs.
- [ ] `# SUMMARY:` line exists in each events CSV.
- [ ] Repeated runs are aggregated into a human-readable table.
- [ ] Mean/variance or equivalent summary statistics are documented.
- [ ] Baseline comparison runs are preserved for all claimed scheduler modes.

Reference:
- `scripts/run_all_schedulers.sh`
- `client/client_qlogger.h`
- `client/client_qlogger.c`
- `pqi_parameters.md`

## 6. Documentation consistency

- [ ] Every run ID mentioned in markdown exists under `experiment_runs/` or another preserved artifact location.
- [ ] `validated_localip_results.md` matches actual saved artifacts.
- [ ] Invalidated public-IP runs are clearly separated from valid local-IP runs.
- [ ] Claimed frame counts / switch counts / success flags are traceable to logs.
- [ ] Final AMR text references only preserved, reproducible runs.

## 7. Final AMR gate

Raise AMR only if all statements below are true.

- [ ] Final valid run set is fixed.
- [ ] Final valid run set is preserved in the repository or an agreed artifact store.
- [ ] Statistical evidence exists for any repeated-experiment claim.
- [ ] Submission document and artifact names are aligned.
- [ ] No known blocker remains open.

If any item above is unchecked, do not raise AMR yet.
