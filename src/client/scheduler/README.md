# src/client/scheduler — modular path schedulers

Scaffold for the paper's empirical comparison. Each scheduler is a swappable
module implementing one `select()` function; `select_send_path()` in
`client_loop.c` dispatches to the module chosen by `MPQUIC_SCHED_MODE`. This
replaces the current inline/monolithic scheduling in `client_loop.c`.

## Common interface (`scheduler.h`)
```c
typedef struct {
    int use_i;           /* chosen path index, or -1 = no usable path */
    int choice_kind;     /* 0 = primary (Wi-Fi), 1 = backup (5G) */
    const char* reason;  /* short reason string, logged to the QoS CSV */
} sched_choice_t;

/* Every scheduler implements this signature. `st` carries the per-path metric
 * arrays (pqi_rtt_ewma[], pqi_loss_bp_ewma[], pqi_bw_ewma[], path_rssi_ewma_dbm[],
 * path_last_* delivery counters) and the switch/hysteresis state. */
sched_choice_t sched_<name>_select(tx_t* st, picoquic_cnx_t* c,
                                   int primary_i, int backup_i, uint64_t now);
```

## Schedulers to implement
Decision: PQI is **not** the proposed method (dated weighted-cost family); the
proposed method is the clean, PQI-free **RSSI-aware** policy. See the paper.

| Module | Role | Decision signal | Status |
|---|---|---|---|
| `sched_minrtt.c`     | baseline        | lowest smoothed RTT (wrap picoquic native) | ☐ wrap existing `select_default_path` |
| `sched_roundrobin.c` | baseline        | fixed alternation over schedulable paths   | ☐ NEW (absent in C today) |
| `sched_rssi_aware.c` | **PROPOSED**    | Wi-Fi RSSI EWMA trend + 4-state FSM + hysteresis (NO PQI cost) | ☐ extract clean, drop PQI dependency |
| `sched_spquic.c`     | baseline        | single active path + connection migration on failure | ☐ wrap existing `select_spquic_path` |
| `sched_pqi.c`        | legacy/compared | α·nRTT+β·nLoss+γ·(1−nBW) min-max + hysteresis FSM | ☐ extract from inline (kept for comparison only) |

## Optional (deterministic → implementable; strengthen the comparison)
| Module | Decision signal |
|---|---|
| `sched_ecf.c`   | Earliest Completion First: RTT+cwnd; wait for fast path if it completes sooner |
| `sched_blest.c` | Blocking-estimation: skip slower path if it would HoL-block the receiver |
| `sched_tof.c`   | Time-in-Flight metric instead of SRTT; detects sudden degradation fastest |

Learning-based (Peekaboo/FALCON/MARS/RL) are **out of scope** for implementation
(need training/bespoke stacks); they are covered by the algorithmic comparison in
the paper's Related Work only.

## Mapping to experiment groups (paper's 4-method core)
SP-QUIC+migration (`sched_spquic`) · MP round-robin (`sched_roundrobin`) ·
MP min-RTT (`sched_minrtt`) · **RSSI-aware (`sched_rssi_aware`, proposed)**.
PQI/ECF/BLEST/ToF are extra baselines if time allows.

## TODO (wiring, after stubs)
- add `sched_choice_t` + `scheduler_mode_*` entries; extend the `MPQUIC_SCHED_MODE`
  parser (currently pqi/rssi/default/spquic) with round-robin, min-rtt, ecf, ...
- refactor `select_send_path()` to dispatch into these modules
- add the new `.c` files to `CMakeLists.txt`
- keep the QoS CSV `reason`/`choice_kind` semantics identical (metrics.py depends on them)
