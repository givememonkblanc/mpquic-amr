# PQI Parameter Reference & Reviewer Mapping

## 1. Scheduler Modes

| Mode | ID | Env Value | Description | Reviewer |
|------|----|-----------|-------------|----------|
| PQI | 0 | `pqi` | Proposed PQI-based scheduler: EWMA smoothing + min-max normalization + hysteresis FSM | R3-#1 (novelty isolation) |
| RSSI-aware | 1 | `rssi` | PQI + Wi-Fi RSSI penalty + preemptive handover + RSSI-driven failback | R3-#1, R2-#3 |
| Default MP-QUIC | 2 | `default` | Baseline: lowest-RTT verified path (picoquic native heuristic) | R1-#10, R3-#4 |
| SP-QUIC + migration | 3 | `spquic` | Baseline: single-path + QUIC connection migration (RFC 9000 §9) | R1-#10, R2-#3 |

Selection via `MPQUIC_SCHED_MODE` environment variable.

## 2. Composite PQI Score

**Formula:**
```
PQI = α · norm(RTT) + β · norm(loss) + γ · (1 − norm(BW)) + ω · norm(RSSI_penalty)
```

**Weights (defined in `client_loop.c`):**

| Parameter | Symbol | Value (scaled) | Actual |
|-----------|--------|----------------|--------|
| RTT weight | α | `PQI_ALPHA = 450` | 0.45 |
| Loss weight | β | `PQI_BETA = 350` | 0.35 |
| BW weight | γ | `PQI_GAMMA = 200` | 0.20 |
| RSSI penalty weight | ω | `PQI_RSSI_WEIGHT = 300` | 0.30 (relative to 1000) |

**Normalization (min-max per decision cycle):**
```
norm(x) = clamp(((x − x_min) / (x_max − x_min)) × 1000, 0, 1000)
```
where min/max are taken across the two active paths (grade 0/1 only).

## 3. EWMA Smoothing

**Update rule:** `S_t = λ · M_t + (1 − λ) · S_{t-1}`

| Metric | Symbol | Value | λ |
|--------|--------|-------|---|
| RTT | `EWMA_RTT_ALPHA` | 45 | 0.45 |
| Loss (basis points) | `EWMA_LOSS_BETA` | 35 | 0.35 |
| Bandwidth | `EWMA_BW_GAMMA` | 20 | 0.20 |

## 4. Path Grade Thresholds

| Grade | Condition | Meaning |
|-------|-----------|---------|
| 0 (good) | verified AND healthy AND RTT ≤ 250ms AND loss ≤ 3% AND RSSI > BAD(−75dBm) | Normal operation |
| 1 (degraded) | unverified OR unhealthy OR RTT > 250ms OR loss > 3% OR RSSI ≤ BAD | Impaired but usable |
| 2 (unusable) | stale (silence > 8s) OR RSSI ≤ UNUSABLE(−82dBm) | Path excluded |

Score mapping: grade 2 → 1000, grade 0 → 0 (single), grade 1 → 500 (single).

## 5. State Machine Thresholds

| Parameter | Value | Description |
|-----------|-------|-------------|
| `PQI_DEGRADE_SCORE` | 650 | Failover when primary score ≥ this |
| `PQI_RECOVER_SCORE` | 450 | Failback when primary score ≤ this |
| `PQI_SWITCH_MARGIN` | 120 | Hysteresis margin (prevents ping-pong) |
| `PQI_FAILBACK_STABLE_US` | 3,000,000 (3s) | Minimum backup tenure before failback |
| `PQI_SWITCH_DEBOUNCE_US` | 2,000,000 (2s) | Min interval between switches |
| `PQI_PATH_SILENCE_US` | 8,000,000 (8s) | Path stale timeout |

## 6. RSSI Thresholds (dBm)

| Threshold | Value | Link State |
|-----------|-------|------------|
| `RSSI_GOOD_DBM` | −55 | good (≥ −55) |
| `RSSI_DEGRADE_DBM` | −67 | degrading (≤ −67) |
| `RSSI_BAD_DBM` | −75 | bad (≤ −75) |
| `RSSI_UNUSABLE_DBM` | −82 | unusable (≤ −82) |

RSSI penalty formula (linear):
```
penalty = 0                           if rssi ≥ GOOD
penalty = 1000                        if rssi ≤ UNUSABLE
penalty = (GOOD − rssi) × 1000 / (GOOD − UNUSABLE)   otherwise
```

## 7. Path Metrics Source (picoquic_path_t)

| Metric | Field | Unit |
|--------|-------|------|
| RTT | `smoothed_rtt` | µs |
| Loss | `total_bytes_lost` / delta over `bytes_sent` | basis points (0-10000) |
| Bandwidth | `receive_rate_estimate` or `bandwidth_estimate` | bytes/s |
| Verified | `first_tuple->challenge_verified` | bool |
| Delivered | `delivered` | packet count |
| In flight | `bytes_in_transit` | bytes |
| Last received | `last_packet_received_at` | µs |

## 8. Experiment Configuration

| Parameter | Default | Override |
|-----------|---------|----------|
| Duration | 30 s | `MPQUIC_EXP_DURATION_US` env var |
| Scheduler mode | rssi | `MPQUIC_SCHED_MODE` env var |
| Server port | 4433 | CLI arg 3 |
| Frame source | Real camera | N/A |
| Wi-Fi ifname | wlP1p1s0 | Hard-coded |

## 9. Baseline Scheduler Behavior

### Default MP-QUIC (minRTT)
- Selects verified path with lowest `smoothed_rtt`
- No hysteresis, no probing preference
- Approximates picoquic internal default scheduler

### SP-QUIC + Connection Migration (RFC 9000 §9)
- Uses only primary local IP
- On primary failure, migrates to first available verified path
- No multipath awareness

## 10. Reviewer Comment Mapping

| Reviewer | Comment | Implementation/Response |
|----------|---------|------------------------|
| R1-#6 | Min-max normalization not described | Documented in §2 above + `client_loop.c` inline |
| R1-#7 | PQI definition not explicit | Formula in §2 + code comment block |
| R1-#8 | Path probing strategy undefined | Documented in §7 + `client_loop.c` probing comments |
| R1-#9 | Frame boundary detection | MPQ1 magic in `send_frame_on_path()` |
| R1-#10 | Missing baseline comparisons | Modes 2 (default) and 3 (spquic) added |
| R3-#1 | Novelty unclear | PQI = EWMA + norm + hysteresis FSM for AMR handover |
| R3-#3 | Parameters not specified | This document + inline code constants |
| R3-#4 | No std MP-QUIC comparison | Mode 2 (default) = picoquic native scheduler |
| R3-#5 | Implementation details | picoquic MP-QUIC draft-21 based, scheduler in `select_send_path()` |
| R3-#8 | Repeated experiments + stats | QoS logger CSV output (`client_qlogger.c`) |
| R3-#7 | 70ms hesitation | `outage_us` column in events.csv captures true inter-frame gaps |
| R2-#3 | Handover vs failover clarity | Mode 3 (spquic) isolates single-path migration behavior |
