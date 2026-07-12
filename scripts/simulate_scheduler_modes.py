#!/usr/bin/env python3
"""
MP-QUIC Scheduler Mode Simulator
==================================

Compares scheduler decisions across all four modes:
  - pqi:      PQI-based (RTT/loss/BW EWMA + min-max norm + hysteresis)
  - rssi:     RSSI-aware variant (adds Wi-Fi RSSI penalty + preemptive handover)
  - default:  Baseline minRTT (lowest-RTT verified path)
  - spquic:   Baseline SP-QUIC + connection migration (primary-only)

Reviewer mapping:
  R1-#10, R3-#4: baseline comparison methodology
  R3-#1:         PQI/RSSI novelty isolation vs standard approaches
  R3-#3:         parameter transparency for reproducibility
"""

from dataclasses import dataclass

# ─── PQI Parameters (matches client_loop.c definitions) ───
PQI_ALPHA = 450
PQI_BETA = 350
PQI_GAMMA = 200
PQI_RSSI_WEIGHT = 300
PQI_DEGRADE_SCORE = 650
PQI_RECOVER_SCORE = 450
PQI_SWITCH_MARGIN = 120
PQI_FAILBACK_STABLE_US = 3_000_000
PQI_SWITCH_DEBOUNCE_US = 2_000_000

# ─── RSSI Thresholds (dBm) ───
RSSI_GOOD_DBM = -55
RSSI_DEGRADE_DBM = -67
RSSI_BAD_DBM = -75
RSSI_UNUSABLE_DBM = -82


@dataclass
class Path:
    name: str
    rtt_us: int
    loss_bp: int
    bw: int
    rssi_dbm: int | None
    usable: bool = True
    verified: bool = True  # for spquic/default mode: only verified paths eligible


def clamp_norm(value: int, min_v: int, max_v: int) -> int:
    if max_v <= min_v:
        return 0
    if value <= min_v:
        return 0
    if value >= max_v:
        return 1000
    return ((value - min_v) * 1000) // (max_v - min_v)


def rssi_penalty(rssi_dbm: int | None) -> int:
    if rssi_dbm is None:
        return 0
    if rssi_dbm >= RSSI_GOOD_DBM:
        return 0
    if rssi_dbm <= RSSI_UNUSABLE_DBM:
        return 1000
    return ((RSSI_GOOD_DBM - rssi_dbm) * 1000) // (RSSI_GOOD_DBM - RSSI_UNUSABLE_DBM)


def wifi_state(rssi_dbm: int | None) -> str:
    if rssi_dbm is None:
        return "unknown"
    if rssi_dbm <= RSSI_UNUSABLE_DBM:
        return "unusable"
    if rssi_dbm <= RSSI_BAD_DBM:
        return "bad"
    if rssi_dbm <= RSSI_DEGRADE_DBM:
        return "degrading"
    return "good"


# ══════════════════════════════════════════════════════════════════
#  Mode-specific selection logic
# ══════════════════════════════════════════════════════════════════

def choose_default(primary: Path, backup: Path) -> tuple[int, str, int, int]:
    """Baseline minRTT: select verified path with lowest RTT."""
    candidates = []
    if primary.usable and primary.verified:
        candidates.append((primary.rtt_us, 0))
    if backup.usable and backup.verified:
        candidates.append((backup.rtt_us, 1))
    if not candidates:
        return 0, "no_verified_path", 0, 0
    candidates.sort(key=lambda x: x[0])
    choice = candidates[0][1]
    reason = "minRTT" if len(candidates) > 1 else "only_verified"
    return choice, reason, primary.rtt_us, backup.rtt_us


def choose_spquic(primary: Path, backup: Path, last_choice: int) -> tuple[int, str, int, int]:
    """SP-QUIC + migration: use primary; migrate only if primary fails."""
    if primary.usable and primary.verified:
        return 0, "spquic_primary", 0, 0
    if backup.usable and backup.verified:
        return 1, "spquic_migrated", 0, 0
    return last_choice, "spquic_no_path", 0, 0


def compute_pqi_scores(primary: Path, backup: Path, mode: str) -> tuple[int, int]:
    paths = [p for p in (primary, backup) if p.usable]
    if len(paths) < 2:
        def single_score(p: Path) -> int:
            return 0 if p.usable else 1000
        return single_score(primary), single_score(backup)

    min_rtt = min(p.rtt_us for p in paths)
    max_rtt = max(p.rtt_us for p in paths)
    min_loss = min(p.loss_bp for p in paths)
    max_loss = max(p.loss_bp for p in paths)
    min_bw = min(p.bw for p in paths)
    max_bw = max(p.bw for p in paths)

    def score(p: Path) -> int:
        if not p.usable:
            return 1000
        nrtt = clamp_norm(p.rtt_us, min_rtt, max_rtt)
        nloss = clamp_norm(p.loss_bp, min_loss, max_loss)
        nbw = clamp_norm(p.bw, min_bw, max_bw)
        nrssi = rssi_penalty(p.rssi_dbm) if mode == "rssi" else 0
        return (PQI_ALPHA * nrtt + PQI_BETA * nloss + PQI_GAMMA * (1000 - nbw) + PQI_RSSI_WEIGHT * nrssi) // (1000 + PQI_RSSI_WEIGHT)

    return score(primary), score(backup)


def choose_pqi(mode: str, primary: Path, backup: Path,
               last_choice: int, last_switch_us: int,
               choice_since_us: int, now: int):
    """PQI/RSSI-aware state machine (identical to client_loop.c logic)."""
    primary_score, backup_score = compute_pqi_scores(primary, backup, mode)
    primary_usable = primary_score < 1000
    backup_usable = backup_score < 1000
    state = wifi_state(primary.rssi_dbm)

    if not primary_usable and not backup_usable:
        return last_choice, "both_unusable", primary_score, backup_score
    if primary_usable and not backup_usable:
        return 0, "primary_only", primary_score, backup_score
    if not primary_usable and backup_usable:
        return 1, "backup_only", primary_score, backup_score

    if last_choice >= 0 and last_switch_us and now - last_switch_us <= PQI_SWITCH_DEBOUNCE_US:
        return last_choice, "debounce_hold", primary_score, backup_score

    if last_choice < 0:
        if primary_score <= backup_score + PQI_SWITCH_MARGIN:
            return 0, "prefer_primary", primary_score, backup_score
        return 1, "better_backup", primary_score, backup_score

    if last_choice == 0:
        if mode == "rssi" and state in ("bad", "unusable") and backup_usable:
            return 1, "rssi_preemptive_handover", primary_score, backup_score
        if primary_score >= PQI_DEGRADE_SCORE and backup_score + PQI_SWITCH_MARGIN < primary_score:
            return 1, "degrade_failover", primary_score, backup_score
        return 0, "hold_primary", primary_score, backup_score

    if mode == "rssi" and state == "good" and primary_usable \
       and choice_since_us and now - choice_since_us >= PQI_FAILBACK_STABLE_US \
       and primary_score <= backup_score + PQI_SWITCH_MARGIN:
        return 0, "rssi_recover_primary", primary_score, backup_score
    if choice_since_us and now - choice_since_us >= PQI_FAILBACK_STABLE_US \
       and primary_score <= PQI_RECOVER_SCORE \
       and primary_score + PQI_SWITCH_MARGIN < backup_score:
        return 0, "stable_failback", primary_score, backup_score
    return 1, "hold_backup", primary_score, backup_score


# ══════════════════════════════════════════════════════════════════
#  Scenarios
# ══════════════════════════════════════════════════════════════════

SCENARIOS = {
    "static_good": [
        (0, Path("wifi", 12_000, 80, 900_000, -52), Path("backup", 20_000, 120, 700_000, None)),
        (2_000_000, Path("wifi", 12_500, 90, 890_000, -53), Path("backup", 20_000, 120, 700_000, None)),
        (5_000_000, Path("wifi", 12_300, 85, 905_000, -52), Path("backup", 20_000, 120, 700_000, None)),
    ],
    "gradual_degrade_recover": [
        (0, Path("wifi", 12_000, 80, 900_000, -52), Path("backup", 20_000, 120, 700_000, None)),
        (1_000_000, Path("wifi", 18_000, 130, 820_000, -66), Path("backup", 19_000, 120, 700_000, None)),
        (2_000_000, Path("wifi", 30_000, 220, 600_000, -72), Path("backup", 19_000, 120, 700_000, None)),
        (3_500_000, Path("wifi", 42_000, 260, 520_000, -77), Path("backup", 18_000, 110, 710_000, None)),
        (7_000_000, Path("wifi", 16_000, 100, 870_000, -58), Path("backup", 18_000, 110, 710_000, None)),
    ],
    "abrupt_drop_recover": [
        (0, Path("wifi", 11_000, 70, 910_000, -50), Path("backup", 22_000, 130, 690_000, None)),
        (1_500_000, Path("wifi", 55_000, 400, 300_000, -81), Path("backup", 21_000, 125, 700_000, None)),
        (4_500_000, Path("wifi", 15_000, 100, 860_000, -57), Path("backup", 21_000, 125, 700_000, None)),
    ],
}


def run(mode: str, scenario_name: str, scenario_steps):
    print(f"\n{'='*60}")
    print(f"  mode={mode:>8}  scenario={scenario_name}")
    print(f"{'='+'-'*58}+")
    print(f"  {'t(s)':>6} {'wifi_state':>12} {'decision':>28}")
    print(f"{'-'*60}")

    last_choice = -1
    last_switch_us = 0
    choice_since_us = 0

    for now, primary, backup in scenario_steps:
        if mode == "default":
            choice, reason, _, _ = choose_default(primary, backup)
        elif mode == "spquic":
            choice, reason, _, _ = choose_spquic(primary, backup, last_choice)
        else:
            choice, reason, p_score, b_score = choose_pqi(
                mode, primary, backup, last_choice, last_switch_us, choice_since_us, now
            )

        if choice != last_choice:
            last_choice = choice
            last_switch_us = now
            choice_since_us = now

        state = wifi_state(primary.rssi_dbm)
        choice_label = "wifi" if choice == 0 else "backup"
        print(f"  {now/1e6:>6.1f}s  {state:>12}  {choice_label+': '+reason:<28}")


if __name__ == "__main__":
    modes = ["pqi", "rssi", "default", "spquic"]
    for scenario_name, scenario_steps in SCENARIOS.items():
        for mode in modes:
            run(mode, scenario_name, scenario_steps)
