#!/usr/bin/env python3
import argparse
import csv
import http.server
import io
import json
import os
import re
from urllib.parse import parse_qs, urlparse
from pathlib import Path

try:
    from PIL import Image
    import numpy as np
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

parser = argparse.ArgumentParser(description="MP-QUIC Stream Monitor")
parser.add_argument("--frames-dir", default="/tmp/frames_test_final", help="Directory where server saves frame_* files")
parser.add_argument("--port", type=int, default=8081, help="HTTP server port")
args = parser.parse_args()

FRAMES_DIR = Path(args.frames_dir).resolve()
PORT = args.port
REPO_ROOT = Path(__file__).resolve().parent.parent
QLOG_DIR = REPO_ROOT / "results" / "qlogs_client"


def _jet_colormap():
    lut = []
    for i in range(256):
        r = g = b = 0
        if i < 32:
            b = 128 + i * 4
        elif i < 96:
            b = 255
            g = (i - 32) * 4
        elif i < 160:
            r = (i - 96) * 4
            g = 255
            b = 255 - (i - 96) * 4
        elif i < 224:
            r = 255
            g = 255 - (i - 160) * 4
            b = 0
        else:
            r = 255 - (i - 224) * 4
            g = 0
            b = 0
        lut.append((min(r, 255), min(g, 255), min(b, 255)))
    return lut


_JET_LUT = _jet_colormap()


def _normalize_depth_to_jet(arr):
    flat = arr.ravel()
    if flat.size == 0:
        return None
    sorted_px = np.sort(flat)
    n = len(sorted_px)
    vmin = sorted_px[max(0, n // 50)]
    vmax = sorted_px[min(n - 1, (n * 49) // 50)]
    if vmax <= vmin:
        vmax = vmin + 1.0
    idx = np.clip(((arr - vmin) * (255.0 / (vmax - vmin))), 0, 255).astype(np.uint8)
    jet_rgb = np.zeros((*idx.shape, 3), dtype=np.uint8)
    for i in range(256):
        r, g, b = _JET_LUT[i]
        mask = idx == i
        jet_rgb[mask, 0] = r
        jet_rgb[mask, 1] = g
        jet_rgb[mask, 2] = b
    return jet_rgb


def get_latest_pair():
    if not FRAMES_DIR.is_dir():
        return None, None, 0

    depth_files = sorted(FRAMES_DIR.glob("*_d.png"))
    rgb_files = sorted(FRAMES_DIR.glob("*_r.jpg"))
    if not depth_files or not rgb_files:
        return None, None, 0

    depth_indices = set()
    for f in depth_files:
        m = re.search(r"frame_(\d+)_d\.png", f.name)
        if m:
            depth_indices.add(int(m.group(1)))

    rgb_pairs = {}
    for f in rgb_files:
        m = re.search(r"frame_(\d+)_r\.jpg", f.name)
        if m:
            rgb_pairs[int(m.group(1))] = f

    common = sorted(depth_indices & set(rgb_pairs.keys()))
    if not common:
        return None, None, 0

    latest_idx = common[-1]
    depth_path = FRAMES_DIR / f"frame_{latest_idx:06d}_d.png"
    rgb_path = rgb_pairs[latest_idx]
    if not depth_path.is_file() or not rgb_path.is_file():
        return None, None, 0
    return str(depth_path), str(rgb_path), latest_idx


def get_stats():
    depth_path, rgb_path, pair_idx = get_latest_pair()
    latest_name = None
    latest_mtime = 0
    if rgb_path and os.path.isfile(rgb_path):
        latest_name = os.path.basename(rgb_path)
        latest_mtime = os.path.getmtime(rgb_path)

    network_stats = None
    stats_json = FRAMES_DIR / "stats.json"
    if stats_json.is_file():
        try:
            network_stats = json.loads(stats_json.read_text())
        except Exception:
            network_stats = None

    return {
        "frame_count": pair_idx,
        "latest_name": latest_name,
        "latest_mtime": latest_mtime,
        "pair_idx": pair_idx,
        "has_depth": depth_path is not None,
        "has_rgb": rgb_path is not None,
        "network_stats": network_stats,
    }


def make_composite_jpeg(depth_path, rgb_path):
    if not HAS_PIL:
        return None
    try:
        rgb_img = Image.open(rgb_path).convert("RGB")
        rgb_arr = np.array(rgb_img, dtype=np.uint8)
        depth_img = Image.open(depth_path)
        depth_arr = np.array(depth_img, dtype=np.float32)
    except Exception:
        return None

    if depth_arr.shape[:2] != rgb_arr.shape[:2]:
        depth_img = depth_img.resize((rgb_img.width, rgb_img.height), Image.NEAREST)
        depth_arr = np.array(depth_img, dtype=np.float32)

    jet_rgb = _normalize_depth_to_jet(depth_arr)
    if jet_rgb is None:
        buf = io.BytesIO()
        rgb_img.save(buf, format="JPEG", quality=85)
        return buf.getvalue()

    mask = depth_arr > 0
    alpha = 0.6
    out = rgb_arr.copy()
    for c in range(3):
        out[:, :, c] = np.where(mask, (alpha * jet_rgb[:, :, c] + (1 - alpha) * rgb_arr[:, :, c]).astype(np.uint8), rgb_arr[:, :, c])

    out_img = Image.fromarray(out, "RGB")
    buf = io.BytesIO()
    out_img.save(buf, format="JPEG", quality=85)
    return buf.getvalue()


def _read_csv_rows(path):
    if not path.is_file():
        return []
    rows = []
    try:
        with open(path, newline="") as f:
            reader = csv.DictReader(line for line in f if not line.startswith("# SUMMARY"))
            for row in reader:
                rows.append(row)
    except Exception:
        return []
    return rows


def _downsample(rows, limit=180):
    if len(rows) <= limit:
        return rows
    step = max(1, len(rows) // limit)
    sampled = rows[::step]
    if sampled[-1] is not rows[-1]:
        sampled.append(rows[-1])
    return sampled


def list_experiment_runs():
    runs = []
    if not QLOG_DIR.is_dir():
        return runs

    event_files = sorted(QLOG_DIR.glob("*_events.csv"))
    for event_path in event_files:
        run_id = event_path.name[:-11]
        snap_path = QLOG_DIR / f"{run_id}_snap.csv"
        event_rows = _read_csv_rows(event_path)
        snap_rows = _read_csv_rows(snap_path)
        if not event_rows:
            continue

        first_t = int(event_rows[0]["t_us"])
        last_t = int(event_rows[-1]["t_us"])
        duration_s = max(0.0, (last_t - first_t) / 1_000_000.0)
        frames = len(event_rows)
        avg_rtt_ms = sum(int(r.get("rtt_us", 0)) for r in event_rows) / max(1, frames) / 1000.0
        total_bytes = int(event_rows[-1].get("cum_bytes", 0))
        max_switch = max(int(r.get("switch_count", 0)) for r in event_rows)
        max_outage_ms = max(int(r.get("outage_us", 0)) for r in event_rows) / 1000.0
        scheduler = run_id.split("_")[0] if "_" in run_id else run_id
        host = run_id.split("_", 1)[1] if "_" in run_id else "unknown"

        runs.append({
            "run_id": run_id,
            "scheduler": scheduler,
            "host": host,
            "frames": frames,
            "duration_s": round(duration_s, 2),
            "avg_rtt_ms": round(avg_rtt_ms, 2),
            "switch_count": max_switch,
            "max_outage_ms": round(max_outage_ms, 2),
            "total_mb": round(total_bytes / 1024 / 1024, 2),
            "has_snap": snap_path.is_file() and bool(snap_rows),
        })

    runs.sort(key=lambda r: (r["scheduler"], r["run_id"]), reverse=True)
    return runs


def get_experiment_detail(run_id):
    safe = re.sub(r"[^A-Za-z0-9._-]", "", run_id)
    event_path = QLOG_DIR / f"{safe}_events.csv"
    snap_path = QLOG_DIR / f"{safe}_snap.csv"
    event_rows = _read_csv_rows(event_path)
    snap_rows = _read_csv_rows(snap_path)
    if not event_rows:
        return None

    event_rows = _downsample(event_rows, 220)
    snap_rows = _downsample(snap_rows, 180)
    t0 = int(event_rows[0]["t_us"])

    event_series = []
    for r in event_rows:
        event_series.append({
            "t_s": round((int(r["t_us"]) - t0) / 1_000_000.0, 3),
            "path_i": int(r.get("path_i", 0)),
            "rtt_ms": round(int(r.get("rtt_us", 0)) / 1000.0, 3),
            "frame_kb": round(int(r.get("frame_bytes", 0)) / 1024.0, 3),
            "outage_ms": round(int(r.get("outage_us", 0)) / 1000.0, 3),
            "cum_mb": round(int(r.get("cum_bytes", 0)) / 1024.0 / 1024.0, 3),
            "choice_reason": r.get("choice_reason", ""),
            "switch_count": int(r.get("switch_count", 0)),
        })

    snap_by_path = {}
    if snap_rows:
        snap_t0 = int(snap_rows[0]["t_us"])
        for r in snap_rows:
            pid = int(r.get("path_i", 0))
            snap_by_path.setdefault(pid, []).append({
                "t_s": round((int(r["t_us"]) - snap_t0) / 1_000_000.0, 3),
                "srtt_ms": round(int(r.get("srtt_us", 0)) / 1000.0, 3),
                "loss_bytes": int(r.get("loss_bytes", 0)),
                "sent_mb": round(int(r.get("sent_bytes", 0)) / 1024.0 / 1024.0, 3),
                "in_flight_kb": round(int(r.get("in_flight", 0)) / 1024.0, 3),
                "verified": int(r.get("verified", 0)),
                "healthy": int(r.get("healthy", 0)),
            })

    return {
        "run_id": safe,
        "summary": next((r for r in list_experiment_runs() if r["run_id"] == safe), None),
        "events": event_series,
        "snaps": snap_by_path,
    }


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MP-QUIC Experiment Console</title>
<style>
  :root {
    --bg: #0a0f18;
    --panel: #111826;
    --panel-2: #0d1420;
    --line: #263247;
    --text: #e7edf7;
    --muted: #8b98ad;
    --blue: #5ca9ff;
    --green: #41d28d;
    --yellow: #f3ba4f;
    --red: #f36a6a;
    --cyan: #62d7ff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: "Segoe UI", system-ui, sans-serif;
    background: radial-gradient(circle at top, #101a29 0%, var(--bg) 45%);
    color: var(--text);
    padding: 18px;
  }
  .page {
    max-width: 1700px;
    margin: 0 auto;
  }
  .top-nav {
    display: flex;
    gap: 10px;
    margin-bottom: 14px;
  }
  .top-nav a {
    text-decoration: none;
    color: var(--muted);
    border: 1px solid var(--line);
    background: rgba(255,255,255,0.02);
    padding: 8px 12px;
    border-radius: 10px;
    font-size: 12px;
    font-weight: 600;
  }
  .top-nav a.active {
    color: var(--blue);
    border-color: rgba(92,169,255,0.35);
    background: rgba(92,169,255,0.12);
  }
  .compare-panel {
    margin-top: 18px;
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 18px;
    overflow: hidden;
  }
  .compare-body {
    padding: 14px;
    display: grid;
    gap: 14px;
  }
  .compare-selectors {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }
  .selector-box {
    background: var(--panel-2);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 12px;
    display: grid;
    gap: 8px;
  }
  .selector-box label {
    font-size: 11px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: .08em;
  }
  .selector-box select {
    background: #0b111a;
    color: var(--text);
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 10px 12px;
    font-size: 13px;
  }
  .compare-summary {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: 12px;
  }
  .compare-metric {
    background: var(--panel-2);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 12px;
  }
  .compare-metric .k {
    color: var(--muted);
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: .08em;
    margin-bottom: 8px;
  }
  .compare-values {
    display: grid;
    gap: 6px;
    font-size: 13px;
  }
  .runA { color: var(--cyan); }
  .runB { color: var(--yellow); }
  .hero {
    display: flex;
    justify-content: space-between;
    align-items: end;
    gap: 16px;
    margin-bottom: 18px;
  }
  .hero h1 {
    font-size: 28px;
    font-weight: 700;
    letter-spacing: -0.03em;
  }
  .hero p {
    color: var(--muted);
    margin-top: 6px;
    font-size: 13px;
  }
  .hero-badge {
    border: 1px solid var(--line);
    background: rgba(92,169,255,0.08);
    color: var(--blue);
    padding: 8px 12px;
    border-radius: 999px;
    font-size: 12px;
    white-space: nowrap;
  }
  .overview {
    display: grid;
    grid-template-columns: repeat(6, minmax(0, 1fr));
    gap: 12px;
    margin-bottom: 18px;
  }
  .card {
    background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.00));
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 14px 16px;
    box-shadow: 0 14px 40px rgba(0,0,0,0.18);
  }
  .card .label {
    font-size: 11px;
    letter-spacing: 0.08em;
    color: var(--muted);
    text-transform: uppercase;
    margin-bottom: 8px;
  }
  .card .value {
    font-size: 24px;
    font-weight: 700;
    line-height: 1.1;
  }
  .card .sub {
    margin-top: 8px;
    color: var(--muted);
    font-size: 12px;
    min-height: 16px;
  }
  .status-live { color: var(--green); }
  .status-warn { color: var(--yellow); }
  .status-dead { color: var(--red); }
  .layout {
    display: grid;
    grid-template-columns: minmax(720px, 1.3fr) minmax(420px, 0.9fr);
    gap: 18px;
    align-items: start;
  }
  .stage {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 18px;
    overflow: hidden;
  }
  .stage-header, .telemetry-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 16px;
    border-bottom: 1px solid var(--line);
    background: rgba(255,255,255,0.02);
  }
  .section-title {
    font-size: 15px;
    font-weight: 700;
  }
  .section-meta {
    color: var(--muted);
    font-size: 12px;
  }
  .tab-bar { display: flex; gap: 8px; }
  .tab-btn {
    background: transparent;
    border: 1px solid var(--line);
    color: var(--muted);
    padding: 7px 12px;
    border-radius: 10px;
    cursor: pointer;
    font-size: 12px;
  }
  .tab-btn.active {
    background: rgba(92,169,255,0.12);
    color: var(--blue);
    border-color: rgba(92,169,255,0.35);
  }
  .stage-body {
    padding: 16px;
  }
  .frame-shell {
    aspect-ratio: 4 / 3;
    width: 100%;
    background: #06090f;
    border: 1px solid #1a2231;
    border-radius: 14px;
    overflow: hidden;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .frame-shell img {
    width: 100%;
    height: 100%;
    object-fit: contain;
    display: block;
  }
  .stage-footer {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
    margin-top: 14px;
  }
  .mini {
    background: var(--panel-2);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 12px;
  }
  .mini .k {
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .08em;
    margin-bottom: 6px;
  }
  .mini .v {
    font-size: 14px;
    font-weight: 600;
    word-break: break-word;
  }
  .telemetry {
    display: grid;
    gap: 14px;
  }
  .telemetry-panel {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 18px;
    overflow: hidden;
  }
  .runs-panel {
    margin-top: 18px;
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 18px;
    overflow: hidden;
  }
  .runs-layout {
    display: grid;
    grid-template-columns: 320px 1fr;
    min-height: 540px;
  }
  .runs-sidebar {
    border-right: 1px solid var(--line);
    background: rgba(255,255,255,0.015);
    padding: 14px;
    overflow-y: auto;
  }
  .runs-list { display: grid; gap: 10px; }
  .run-item {
    border: 1px solid var(--line);
    background: var(--panel-2);
    border-radius: 12px;
    padding: 12px;
    cursor: pointer;
  }
  .run-item.active {
    border-color: rgba(92,169,255,0.55);
    box-shadow: 0 0 0 1px rgba(92,169,255,0.15) inset;
  }
  .run-top { display: flex; justify-content: space-between; gap: 8px; margin-bottom: 8px; }
  .run-name { font-weight: 700; font-size: 13px; }
  .run-pill {
    font-size: 10px; color: var(--blue); background: rgba(92,169,255,0.12);
    border: 1px solid rgba(92,169,255,0.35); border-radius: 999px; padding: 3px 7px;
  }
  .run-meta { color: var(--muted); font-size: 11px; display: grid; gap: 4px; }
  .runs-main { padding: 14px; display: grid; gap: 14px; }
  .run-summary-grid {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: 12px;
  }
  .chart-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px;
  }
  .chart-card {
    background: var(--panel-2);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 12px;
  }
  .chart-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    margin-bottom: 8px;
  }
  .chart-title { font-size: 13px; font-weight: 700; margin-bottom: 8px; }
  .chart-head .chart-title { margin-bottom: 0; }
  .chart-expand-btn {
    background: rgba(92,169,255,0.10);
    color: var(--blue);
    border: 1px solid rgba(92,169,255,0.28);
    border-radius: 8px;
    padding: 6px 10px;
    font-size: 11px;
    font-weight: 700;
    cursor: pointer;
  }
  .chart-expand-btn:hover {
    background: rgba(92,169,255,0.18);
  }
  .chart-wrap { background: #0b111a; border: 1px solid #1a2433; border-radius: 10px; padding: 8px; }
  .chart-svg { width: 100%; height: 180px; display: block; }
  .chart-legend { color: var(--muted); font-size: 11px; margin-top: 8px; }
  .chart-modal {
    position: fixed;
    inset: 0;
    display: none;
    align-items: center;
    justify-content: center;
    background: rgba(4, 8, 14, 0.78);
    backdrop-filter: blur(6px);
    z-index: 1000;
    padding: 24px;
  }
  .chart-modal.open { display: flex; }
  .chart-modal-panel {
    width: min(1280px, 96vw);
    max-height: 92vh;
    overflow: auto;
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 18px;
    box-shadow: 0 24px 80px rgba(0,0,0,0.45);
    padding: 18px;
  }
  .chart-modal-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 12px;
  }
  .chart-modal-title { font-size: 18px; font-weight: 700; }
  .chart-modal-close {
    background: rgba(243,106,106,0.10);
    color: var(--red);
    border: 1px solid rgba(243,106,106,0.28);
    border-radius: 10px;
    padding: 8px 12px;
    font-size: 12px;
    font-weight: 700;
    cursor: pointer;
  }
  .chart-modal .chart-wrap { padding: 14px; }
  .chart-modal .chart-svg { height: 420px; }
  .chart-modal-legend { margin-top: 12px; color: var(--muted); font-size: 12px; }
  .telemetry-body {
    padding: 14px;
  }
  .path-grid {
    display: grid;
    gap: 12px;
  }
  .path-card {
    background: var(--panel-2);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 14px;
  }
  .path-card.active {
    border-color: rgba(65,210,141,0.65);
    box-shadow: 0 0 0 1px rgba(65,210,141,0.15) inset;
  }
  .path-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    margin-bottom: 12px;
  }
  .path-name {
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 700;
  }
  .badge {
    font-size: 10px;
    padding: 3px 7px;
    border-radius: 999px;
    border: 1px solid transparent;
    white-space: nowrap;
  }
  .badge.active { background: rgba(65,210,141,0.12); border-color: rgba(65,210,141,0.4); color: var(--green); }
  .badge.verified { background: rgba(92,169,255,0.12); border-color: rgba(92,169,255,0.4); color: var(--blue); }
  .badge.unverified { background: rgba(243,106,106,0.12); border-color: rgba(243,106,106,0.4); color: var(--red); }
  .path-metrics {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px 12px;
    margin-bottom: 12px;
  }
  .metric {
    background: rgba(255,255,255,0.015);
    border: 1px solid rgba(255,255,255,0.04);
    border-radius: 10px;
    padding: 10px;
  }
  .metric .k {
    color: var(--muted);
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: .08em;
    margin-bottom: 5px;
  }
  .metric .v {
    font-size: 15px;
    font-weight: 700;
  }
  .path-ip {
    display: grid;
    gap: 6px;
    margin-bottom: 12px;
    color: var(--muted);
    font-size: 12px;
  }
  .path-ip strong { color: var(--text); font-weight: 600; }
  .meter-group { display: grid; gap: 10px; }
  .meter-line { display: grid; gap: 6px; }
  .meter-head {
    display: flex;
    justify-content: space-between;
    font-size: 12px;
  }
  .meter-head span:first-child { color: var(--muted); }
  .bar-bg {
    width: 100%;
    height: 8px;
    background: #202b3e;
    border-radius: 999px;
    overflow: hidden;
  }
  .bar-fg {
    height: 100%;
    width: 0%;
    transition: width 0.35s ease, background-color 0.35s ease;
  }
  .bw-bar { background: linear-gradient(90deg, #3b82f6, #62d7ff); }
  .rtt-bar { background: linear-gradient(90deg, #26c281, #41d28d); }
  .rtt-bar.mid { background: linear-gradient(90deg, #d29922, #f3ba4f); }
  .rtt-bar.high { background: linear-gradient(90deg, #d45151, #f36a6a); }
  .timeline {
    display: grid;
    gap: 8px;
    max-height: 280px;
    overflow-y: auto;
  }
  .event-item {
    border: 1px solid var(--line);
    background: var(--panel-2);
    border-radius: 12px;
    padding: 10px 12px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12px;
    line-height: 1.45;
  }
  .event-item.handover {
    border-color: rgba(243,186,79,0.45);
    background: rgba(243,186,79,0.06);
  }
  .empty {
    color: var(--muted);
    text-align: center;
    padding: 18px 12px;
    border: 1px dashed var(--line);
    border-radius: 12px;
    font-size: 12px;
  }
  @media (max-width: 1320px) {
    .overview { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .layout { grid-template-columns: 1fr; }
    .runs-layout { grid-template-columns: 1fr; }
    .runs-sidebar { border-right: none; border-bottom: 1px solid var(--line); }
    .run-summary-grid, .chart-grid { grid-template-columns: 1fr 1fr; }
  }
  @media (max-width: 760px) {
    body { padding: 12px; }
    .overview { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .stage-footer, .path-metrics { grid-template-columns: 1fr; }
    .hero { align-items: start; flex-direction: column; }
    .main-content { min-width: 0; }
    .run-summary-grid, .chart-grid { grid-template-columns: 1fr; }
    .compare-selectors, .compare-summary { grid-template-columns: 1fr; }
  }
</style>
</head>
<body data-view="__VIEW_MODE__">
<div class="page">
  <div class="top-nav">
    <a href="/live" class="__LIVE_ACTIVE__">Live Monitor</a>
    <a href="/experiments" class="__EXPERIMENTS_ACTIVE__">Experiment Runs</a>
    <a href="/compare" class="__COMPARE_ACTIVE__">Compare Runs</a>
  </div>
  <div class="hero">
    <div>
      <h1>MP-QUIC Experiment Console</h1>
      <p>실험 중 현재 스트림 상태, 경로별 메트릭, 이벤트 전환을 한 화면에서 확인합니다.</p>
    </div>
    <div class="hero-badge">Live monitor · file-backed telemetry</div>
  </div>

  <div class="overview">
    <div class="card"><div class="label">Frame pairs</div><div class="value" id="frameCount">—</div><div class="sub">저장 완료 기준</div></div>
    <div class="card"><div class="label">FPS</div><div class="value" id="fps">—</div><div class="sub">최근 변화량 기반</div></div>
    <div class="card"><div class="label">Active path</div><div class="value" id="activePath">—</div><div class="sub" id="activePathSub">수신 데이터 없음</div></div>
    <div class="card"><div class="label">Connection state</div><div class="value" id="connState">—</div><div class="sub" id="connStateSub">QUIC 상태</div></div>
    <div class="card"><div class="label">Bytes saved</div><div class="value" id="bytesSaved">—</div><div class="sub">서버 저장 누적</div></div>
    <div class="card"><div class="label">Latest frame</div><div class="value" id="latestName">—</div><div class="sub" id="statusLine">waiting</div></div>
  </div>

  <div class="layout" id="liveSection">
    <div class="stage">
      <div class="stage-header">
        <div>
          <div class="section-title">Live stream stage</div>
          <div class="section-meta">현재 선택된 뷰를 실시간으로 갱신합니다.</div>
        </div>
        <div class="tab-bar">
          <button class="tab-btn active" onclick="setView(event, 'composite')">Composite</button>
          <button class="tab-btn" onclick="setView(event, 'rgb')">RGB</button>
          <button class="tab-btn" onclick="setView(event, 'depth')">Depth</button>
        </div>
      </div>
      <div class="stage-body">
        <div class="frame-shell"><img id="frameImage" src="/frame/composite" alt="composite frame"></div>
        <div class="stage-footer">
          <div class="mini"><div class="k">Frames dir</div><div class="v" id="framesDir">/tmp/frames_test_final</div></div>
          <div class="mini"><div class="k">Overlay mode</div><div class="v">RGB + depth jet overlay</div></div>
          <div class="mini"><div class="k">Refresh mode</div><div class="v">Background preloaded swap</div></div>
        </div>
      </div>
    </div>

    <div class="telemetry">
      <div class="telemetry-panel">
        <div class="telemetry-header">
          <div>
            <div class="section-title">Path comparison</div>
            <div class="section-meta" id="netStatus">Waiting for connection...</div>
          </div>
        </div>
        <div class="telemetry-body">
          <div class="path-grid" id="pathGrid"></div>
        </div>
      </div>

      <div class="telemetry-panel">
        <div class="telemetry-header">
          <div>
            <div class="section-title">Event timeline</div>
            <div class="section-meta">핸드오버/활성 경로 변화를 시간순으로 확인</div>
          </div>
        </div>
        <div class="telemetry-body">
          <div class="timeline" id="eventTimeline"></div>
        </div>
      </div>
    </div>
  </div>

  <div class="runs-panel" id="runsSection">
    <div class="telemetry-header">
      <div>
        <div class="section-title">Experiment runs</div>
        <div class="section-meta">qlog CSV 기반 사후 분석 · MLflow 스타일 런 브라우저</div>
      </div>
    </div>
    <div class="runs-layout">
      <div class="runs-sidebar">
        <div class="runs-list" id="runsList"></div>
      </div>
      <div class="runs-main">
        <div class="run-summary-grid" id="runSummaryGrid"></div>
        <div class="chart-grid" id="chartGrid"></div>
      </div>
    </div>
  </div>

  <div class="compare-panel" id="compareSection">
    <div class="telemetry-header">
      <div>
        <div class="section-title">Run comparison</div>
        <div class="section-meta">두 실험을 나란히 비교하고 어떤 설정이 더 좋았는지 판단합니다.</div>
      </div>
    </div>
    <div class="compare-body">
      <div class="compare-selectors">
        <div class="selector-box">
          <label>Run A</label>
          <select id="compareRunA"></select>
        </div>
        <div class="selector-box">
          <label>Run B</label>
          <select id="compareRunB"></select>
        </div>
      </div>
      <div class="compare-summary" id="compareSummary"></div>
      <div class="chart-grid" id="compareCharts"></div>
    </div>
  </div>

  <div class="chart-modal" id="chartModal" onclick="closeChartModal(event)">
    <div class="chart-modal-panel" onclick="event.stopPropagation()">
      <div class="chart-modal-top">
        <div class="chart-modal-title" id="chartModalTitle">Expanded chart</div>
        <button class="chart-modal-close" onclick="forceCloseChartModal()">Close</button>
      </div>
      <div id="chartModalBody"></div>
      <div class="chart-modal-legend" id="chartModalLegend"></div>
    </div>
  </div>
</div>

<script>
let prevCount = 0;
let fpsSamples = [];
let currentView = 'composite';
let selectedRunId = null;
let compareRunA = null;
let compareRunB = null;
const PAGE_VIEW = document.body.dataset.view || 'live';

function formatBytesMB(v) {
  if (v === null || v === undefined) return '—';
  return (v / 1024 / 1024).toFixed(2) + ' MB';
}

function setView(evt, view) {
  currentView = view;
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  if (evt && evt.target) evt.target.classList.add('active');
}

function metricCard(label, value, sub='') {
  return `<div class="card"><div class="label">${label}</div><div class="value">${value}</div><div class="sub">${sub}</div></div>`;
}

function chartCard(title, chartHtml, legendHtml='') {
  const escTitle = title.replace(/"/g, '&quot;');
  const escLegend = legendHtml.replace(/"/g, '&quot;');
  return `
    <div class="chart-card">
      <div class="chart-head">
        <div class="chart-title">${title}</div>
        <button class="chart-expand-btn" onclick='openChartModal(this, ${JSON.stringify(title)}, ${JSON.stringify(legendHtml)})'>Expand</button>
      </div>
      <div class="chart-wrap">${chartHtml}</div>
      <div class="chart-legend">${legendHtml}</div>
    </div>`;
}

function openChartModal(btn, title, legendHtml) {
  const card = btn.closest('.chart-card');
  if (!card) return;
  const wrap = card.querySelector('.chart-wrap');
  const modal = document.getElementById('chartModal');
  document.getElementById('chartModalTitle').textContent = title || 'Expanded chart';
  document.getElementById('chartModalBody').innerHTML = wrap ? wrap.outerHTML : '';
  document.getElementById('chartModalLegend').innerHTML = legendHtml || '';
  modal.classList.add('open');
}

function forceCloseChartModal() {
  document.getElementById('chartModal').classList.remove('open');
}

function closeChartModal(evt) {
  if (evt.target.id === 'chartModal') {
    forceCloseChartModal();
  }
}

function makePolyline(points, color, width=2) {
  if (!points.length) return '';
  return `<polyline fill="none" stroke="${color}" stroke-width="${width}" points="${points.map(p => `${p[0]},${p[1]}`).join(' ')}" />`;
}

function makeStepPolyline(points, color, width=2) {
  if (!points.length) return '';
  let d = `M ${points[0][0]} ${points[0][1]}`;
  for (let i = 1; i < points.length; i++) {
    d += ` L ${points[i][0]} ${points[i-1][1]} L ${points[i][0]} ${points[i][1]}`;
  }
  return `<path d="${d}" fill="none" stroke="${color}" stroke-width="${width}" stroke-linejoin="round" stroke-linecap="round" />`;
}

function niceMax(v) {
  if (v <= 1) return 1;
  const magnitude = Math.pow(10, Math.floor(Math.log10(v)));
  const residual = v / magnitude;
  if (residual <= 1) return magnitude;
  if (residual <= 2) return 2 * magnitude;
  if (residual <= 5) return 5 * magnitude;
  return 10 * magnitude;
}

function buildLineChart(series, xKey, yKey, color, opts={}) {
  const width = 560, height = 220, padL = 54, padR = 14, padT = 14, padB = 34;
  const { maxY=null, xLabel='Time (s)', yLabel='', mode='line', yFmt=(v)=>String(v) } = opts;
  if (!series || series.length === 0) {
    return `<svg class="chart-svg" viewBox="0 0 ${width} ${height}"><text x="50%" y="50%" fill="#8b98ad" text-anchor="middle">No data</text></svg>`;
  }
  const xs = series.map(s => Number(s[xKey] || 0));
  const ys = series.map(s => Number(s[yKey] || 0));
  const xMin = Math.min(...xs), xMax = Math.max(...xs, 1);
  const yMin = 0;
  const rawYMax = maxY !== null ? maxY : Math.max(...ys, 1);
  const yMax = niceMax(rawYMax);
  const plotW = width - padL - padR;
  const plotH = height - padT - padB;
  const toX = x => padL + ((x - xMin) / Math.max(1e-9, (xMax - xMin))) * plotW;
  const toY = y => padT + plotH - ((y - yMin) / Math.max(1e-9, (yMax - yMin))) * plotH;
  const points = series.map(s => [toX(Number(s[xKey] || 0)), toY(Number(s[yKey] || 0))]);
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map(r => yMax * r);
  const xTicks = [0, 0.25, 0.5, 0.75, 1].map(r => xMin + (xMax - xMin) * r);
  const gridY = yTicks.map(v => {
    const y = toY(v);
    return `<g><line x1="${padL}" y1="${y}" x2="${width-padR}" y2="${y}" stroke="#223047" stroke-width="1" />
      <text x="${padL-8}" y="${y+4}" fill="#8b98ad" font-size="10" text-anchor="end">${yFmt(v)}</text></g>`;
  }).join('');
  const gridX = xTicks.map(v => {
    const x = toX(v);
    return `<g><line x1="${x}" y1="${padT}" x2="${x}" y2="${height-padB}" stroke="#172233" stroke-width="1" />
      <text x="${x}" y="${height-10}" fill="#8b98ad" font-size="10" text-anchor="middle">${v.toFixed(1)}</text></g>`;
  }).join('');
  const xAxis = `<line x1="${padL}" y1="${height-padB}" x2="${width-padR}" y2="${height-padB}" stroke="#40506a" stroke-width="1.2" />`;
  const yAxis = `<line x1="${padL}" y1="${padT}" x2="${padL}" y2="${height-padB}" stroke="#40506a" stroke-width="1.2" />`;
  const plot = mode === 'step' ? makeStepPolyline(points, color, 2.5) : makePolyline(points, color, 2.5);
  return `<svg class="chart-svg" viewBox="0 0 ${width} ${height}">
    ${gridY}${gridX}${xAxis}${yAxis}${plot}
    <text x="${(padL + width - padR)/2}" y="${height-2}" fill="#8b98ad" font-size="11" text-anchor="middle">${xLabel}</text>
    <text x="14" y="${(padT + height - padB)/2}" fill="#8b98ad" font-size="11" text-anchor="middle" transform="rotate(-90 14 ${(padT + height - padB)/2})">${yLabel}</text>
  </svg>`;
}

function buildPathTimeline(series) {
  const width = 560, height = 220, padL = 54, padR = 14, padT = 18, padB = 34;
  if (!series || series.length === 0) {
    return `<svg class="chart-svg" viewBox="0 0 ${width} ${height}"><text x="50%" y="50%" fill="#8b98ad" text-anchor="middle">No data</text></svg>`;
  }
  const xMax = Math.max(...series.map(s => Number(s.t_s || 0)), 1);
  const usableW = width - padL - padR;
  const lane0 = 60, lane1 = 130;
  const rects = series.map((s, idx) => {
    const x = padL + (Number(s.t_s || 0) / xMax) * usableW;
    const nextT = idx < series.length - 1 ? Number(series[idx + 1].t_s || xMax) : xMax;
    const w = Math.max(2, ((nextT - Number(s.t_s || 0)) / xMax) * usableW);
    const y = Number(s.path_i || 0) === 0 ? lane0 : lane1;
    const fill = Number(s.path_i || 0) === 0 ? '#5ca9ff' : '#f3ba4f';
    return `<rect x="${x}" y="${y}" width="${w}" height="28" rx="5" fill="${fill}" opacity="0.9" />`;
  }).join('');
  const xTicks = [0,0.25,0.5,0.75,1].map(r => xMax * r);
  const gridX = xTicks.map(v => {
    const x = padL + (v / xMax) * usableW;
    return `<g><line x1="${x}" y1="${padT}" x2="${x}" y2="${height-padB}" stroke="#172233" stroke-width="1" />
    <text x="${x}" y="${height-10}" fill="#8b98ad" font-size="10" text-anchor="middle">${v.toFixed(1)}</text></g>`;
  }).join('');
  return `<svg class="chart-svg" viewBox="0 0 ${width} ${height}">
    ${gridX}
    <text x="${padL-8}" y="78" fill="#8b98ad" font-size="12" text-anchor="end">Path 0</text>
    <text x="${padL-8}" y="148" fill="#8b98ad" font-size="12" text-anchor="end">Path 1</text>
    <line x1="${padL}" y1="95" x2="${width-padR}" y2="95" stroke="#223047" stroke-width="1" />
    ${rects}
    <line x1="${padL}" y1="${height-padB}" x2="${width-padR}" y2="${height-padB}" stroke="#40506a" stroke-width="1.2" />
    <text x="${(padL + width - padR)/2}" y="${height-2}" fill="#8b98ad" font-size="11" text-anchor="middle">Time (s)</text>
  </svg>`;
}

function buildMultiLineChart(seriesA, seriesB, xKey, yKey, opts={}) {
  const width = 560, height = 220, padL = 54, padR = 14, padT = 14, padB = 34;
  const { xLabel='Time (s)', yLabel='', yFmt=(v)=>String(v), mode='line' } = opts;
  const a = seriesA || [];
  const b = seriesB || [];
  if (a.length === 0 && b.length === 0) {
    return `<svg class="chart-svg" viewBox="0 0 ${width} ${height}"><text x="50%" y="50%" fill="#8b98ad" text-anchor="middle">No data</text></svg>`;
  }
  const all = [...a, ...b];
  const xs = all.map(s => Number(s[xKey] || 0));
  const ys = all.map(s => Number(s[yKey] || 0));
  const xMin = Math.min(...xs), xMax = Math.max(...xs, 1);
  const yMin = 0, yMax = niceMax(Math.max(...ys, 1));
  const plotW = width - padL - padR;
  const plotH = height - padT - padB;
  const toX = x => padL + ((x - xMin) / Math.max(1e-9, (xMax - xMin))) * plotW;
  const toY = y => padT + plotH - ((y - yMin) / Math.max(1e-9, (yMax - yMin))) * plotH;
  const ptsA = a.map(s => [toX(Number(s[xKey] || 0)), toY(Number(s[yKey] || 0))]);
  const ptsB = b.map(s => [toX(Number(s[xKey] || 0)), toY(Number(s[yKey] || 0))]);
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map(r => yMax * r);
  const xTicks = [0, 0.25, 0.5, 0.75, 1].map(r => xMin + (xMax - xMin) * r);
  const gridY = yTicks.map(v => {
    const y = toY(v);
    return `<g><line x1="${padL}" y1="${y}" x2="${width-padR}" y2="${y}" stroke="#223047" stroke-width="1" /><text x="${padL-8}" y="${y+4}" fill="#8b98ad" font-size="10" text-anchor="end">${yFmt(v)}</text></g>`;
  }).join('');
  const gridX = xTicks.map(v => {
    const x = toX(v);
    return `<g><line x1="${x}" y1="${padT}" x2="${x}" y2="${height-padB}" stroke="#172233" stroke-width="1" /><text x="${x}" y="${height-10}" fill="#8b98ad" font-size="10" text-anchor="middle">${v.toFixed(1)}</text></g>`;
  }).join('');
  const xAxis = `<line x1="${padL}" y1="${height-padB}" x2="${width-padR}" y2="${height-padB}" stroke="#40506a" stroke-width="1.2" />`;
  const yAxis = `<line x1="${padL}" y1="${padT}" x2="${padL}" y2="${height-padB}" stroke="#40506a" stroke-width="1.2" />`;
  const plotA = mode === 'step' ? makeStepPolyline(ptsA, '#62d7ff', 2.5) : makePolyline(ptsA, '#62d7ff', 2.5);
  const plotB = mode === 'step' ? makeStepPolyline(ptsB, '#f3ba4f', 2.5) : makePolyline(ptsB, '#f3ba4f', 2.5);
  return `<svg class="chart-svg" viewBox="0 0 ${width} ${height}">${gridY}${gridX}${xAxis}${yAxis}${plotA}${plotB}<text x="${(padL + width - padR)/2}" y="${height-2}" fill="#8b98ad" font-size="11" text-anchor="middle">${xLabel}</text><text x="14" y="${(padT + height - padB)/2}" fill="#8b98ad" font-size="11" text-anchor="middle" transform="rotate(-90 14 ${(padT + height - padB)/2})">${yLabel}</text></svg>`;
}

async function fetchExperimentRuns() {
  const r = await fetch('/api/experiments');
  return await r.json();
}

async function fetchExperimentDetail(runId) {
  const r = await fetch('/api/experiment?run_id=' + encodeURIComponent(runId));
  return await r.json();
}

function renderRunList(runs) {
  const el = document.getElementById('runsList');
  if (!runs || runs.length === 0) {
    el.innerHTML = '<div class="empty">No qlog runs found.</div>';
    return;
  }
  if (!selectedRunId) selectedRunId = runs[0].run_id;
  el.innerHTML = runs.map(run => `
    <div class="run-item ${selectedRunId === run.run_id ? 'active' : ''}" onclick="selectRun('${run.run_id}')">
      <div class="run-top">
        <div class="run-name">${run.run_id}</div>
        <div class="run-pill">${run.scheduler}</div>
      </div>
      <div class="run-meta">
        <div>host: ${run.host}</div>
        <div>frames: ${run.frames} · duration: ${run.duration_s}s</div>
        <div>avg RTT: ${run.avg_rtt_ms} ms · switches: ${run.switch_count}</div>
      </div>
    </div>`).join('');
}

function renderExperimentDetail(detail) {
  const summary = detail && detail.summary;
  const sumGrid = document.getElementById('runSummaryGrid');
  const chartGrid = document.getElementById('chartGrid');
  if (!summary || !detail) {
    sumGrid.innerHTML = '<div class="empty">Select a run</div>';
    chartGrid.innerHTML = '';
    return;
  }
  sumGrid.innerHTML = [
    metricCard('Run', summary.run_id, summary.scheduler),
    metricCard('Frames', summary.frames, `${summary.duration_s}s duration`),
    metricCard('Avg RTT', `${summary.avg_rtt_ms} ms`, 'events.csv'),
    metricCard('Switches', summary.switch_count, `max outage ${summary.max_outage_ms} ms`),
    metricCard('Total sent', `${summary.total_mb} MB`, summary.has_snap ? 'snap available' : 'events only')
  ].join('');

  const events = detail.events || [];
  const snaps0 = (detail.snaps && detail.snaps['0']) || [];
  const snaps1 = (detail.snaps && detail.snaps['1']) || [];
  chartGrid.innerHTML = [
    chartCard('RTT over time', buildLineChart(events, 't_s', 'rtt_ms', '#62d7ff', {mode:'step', xLabel:'Time (s)', yLabel:'RTT (ms)', yFmt:(v)=>v.toFixed(1)}), 'Legend: cyan staircase = per-frame RTT from events.csv'),
    chartCard('Path selection timeline', buildPathTimeline(events), 'Legend: blue = Path 0, amber = Path 1'),
    chartCard('Outage gap', buildLineChart(events, 't_s', 'outage_ms', '#f3ba4f', {xLabel:'Time (s)', yLabel:'Outage (ms)', yFmt:(v)=>v.toFixed(0)}), 'Legend: amber line = inter-frame outage / gap'),
    chartCard('Cumulative bytes', buildLineChart(events, 't_s', 'cum_mb', '#41d28d', {xLabel:'Time (s)', yLabel:'Cumulative MB', yFmt:(v)=>v.toFixed(1)}), 'Legend: green line = cumulative transmitted MB'),
    chartCard('Path 0 snapshot RTT', buildLineChart(snaps0, 't_s', 'srtt_ms', '#5ca9ff', {mode:'step', xLabel:'Time (s)', yLabel:'sRTT (ms)', yFmt:(v)=>v.toFixed(1)}), 'Legend: blue staircase = path 0 smoothed RTT from snap.csv'),
    chartCard('Path 1 snapshot RTT', buildLineChart(snaps1, 't_s', 'srtt_ms', '#f3ba4f', {mode:'step', xLabel:'Time (s)', yLabel:'sRTT (ms)', yFmt:(v)=>v.toFixed(1)}), 'Legend: amber staircase = path 1 smoothed RTT from snap.csv')
  ].join('');
}

async function selectRun(runId) {
  selectedRunId = runId;
  const runs = await fetchExperimentRuns();
  renderRunList(runs);
  const detail = await fetchExperimentDetail(runId);
  renderExperimentDetail(detail);
}

async function refreshExperiments() {
  if (PAGE_VIEW !== 'experiments') return;
  try {
    const runs = await fetchExperimentRuns();
    renderRunList(runs);
    if (selectedRunId) {
      const detail = await fetchExperimentDetail(selectedRunId);
      renderExperimentDetail(detail);
    }
  } catch (e) {
    document.getElementById('runsList').innerHTML = '<div class="empty">Failed to load experiment runs.</div>';
  }
}

function compareMetricCard(label, a, b) {
  return `<div class="compare-metric"><div class="k">${label}</div><div class="compare-values"><div class="runA">A: ${a}</div><div class="runB">B: ${b}</div></div></div>`;
}

function renderCompareDetail(detailA, detailB) {
  const summaryEl = document.getElementById('compareSummary');
  const chartsEl = document.getElementById('compareCharts');
  if (!detailA || !detailB || !detailA.summary || !detailB.summary) {
    summaryEl.innerHTML = '<div class="empty">Select two runs to compare.</div>';
    chartsEl.innerHTML = '';
    return;
  }
  const a = detailA.summary;
  const b = detailB.summary;
  summaryEl.innerHTML = [
    compareMetricCard('Scheduler', a.scheduler, b.scheduler),
    compareMetricCard('Frames', a.frames, b.frames),
    compareMetricCard('Avg RTT', `${a.avg_rtt_ms} ms`, `${b.avg_rtt_ms} ms`),
    compareMetricCard('Switches', a.switch_count, b.switch_count),
    compareMetricCard('Max outage', `${a.max_outage_ms} ms`, `${b.max_outage_ms} ms`),
  ].join('');

  const eA = detailA.events || [];
  const eB = detailB.events || [];
  chartsEl.innerHTML = [
    chartCard('RTT comparison', buildMultiLineChart(eA, eB, 't_s', 'rtt_ms', {mode:'step', xLabel:'Time (s)', yLabel:'RTT (ms)', yFmt:(v)=>v.toFixed(1)}), '<span class="runA">Run A = cyan</span> · <span class="runB">Run B = amber</span>'),
    chartCard('Outage comparison', buildMultiLineChart(eA, eB, 't_s', 'outage_ms', {xLabel:'Time (s)', yLabel:'Outage (ms)', yFmt:(v)=>v.toFixed(0)}), '<span class="runA">Run A = cyan</span> · <span class="runB">Run B = amber</span>'),
    chartCard('Cumulative bytes comparison', buildMultiLineChart(eA, eB, 't_s', 'cum_mb', {xLabel:'Time (s)', yLabel:'Cumulative MB', yFmt:(v)=>v.toFixed(1)}), '<span class="runA">Run A = cyan</span> · <span class="runB">Run B = amber</span>'),
    chartCard('Path timeline comparison', buildPathTimeline(eA), '현재는 Run A의 path timeline을 표시합니다. 원하면 다음으로 Run B stacked compare도 추가할 수 있습니다.')
  ].join('');
}

async function refreshCompare() {
  if (PAGE_VIEW !== 'compare') return;
  try {
    const runs = await fetchExperimentRuns();
    const selA = document.getElementById('compareRunA');
    const selB = document.getElementById('compareRunB');
    if (!compareRunA && runs[0]) compareRunA = runs[0].run_id;
    if (!compareRunB && runs[1]) compareRunB = runs[1].run_id;
    const options = runs.map(r => `<option value="${r.run_id}">${r.run_id}</option>`).join('');
    selA.innerHTML = options;
    selB.innerHTML = options;
    if (compareRunA) selA.value = compareRunA;
    if (compareRunB) selB.value = compareRunB;
    selA.onchange = async (e) => { compareRunA = e.target.value; await refreshCompare(); };
    selB.onchange = async (e) => { compareRunB = e.target.value; await refreshCompare(); };
    const [detailA, detailB] = await Promise.all([
      compareRunA ? fetchExperimentDetail(compareRunA) : Promise.resolve(null),
      compareRunB ? fetchExperimentDetail(compareRunB) : Promise.resolve(null),
    ]);
    renderCompareDetail(detailA, detailB);
  } catch (e) {
    document.getElementById('compareSummary').innerHTML = '<div class="empty">Failed to load compare view.</div>';
  }
}

function buildPathCard(p, ns) {
  const isPrimary = p.id === 0;
  const verified = p.verified === true || p.verified === 'true';
  const active = ns && ns.active_path === p.id;
  let rttClass = 'rtt-bar';
  const rtt = Number(p.rtt_ms || 0);
  const throughput = Number(p.throughput_mbps || 0);
  const rttWidth = Math.min(100, (rtt / 200.0) * 100);
  const bwWidth = Math.min(100, (throughput / 10.0) * 100);
  if (rtt > 100) rttClass += ' high';
  else if (rtt > 40) rttClass += ' mid';

  return `
    <div class="path-card ${active ? 'active' : ''}">
      <div class="path-top">
        <div class="path-name">
          <span>Path ${p.id} ${isPrimary ? '(Primary)' : '(Backup)'}</span>
          ${active ? '<span class="badge active">ACTIVE</span>' : ''}
        </div>
        <div>
          ${verified ? '<span class="badge verified">Verified</span>' : '<span class="badge unverified">Unverified</span>'}
        </div>
      </div>
      <div class="path-ip">
        <div>Local: <strong>${p.local_ip || '—'}</strong></div>
        <div>Remote: <strong>${p.remote_ip || '—'}</strong></div>
      </div>
      <div class="path-metrics">
        <div class="metric"><div class="k">Throughput</div><div class="v">${throughput.toFixed(2)} Mbps</div></div>
        <div class="metric"><div class="k">RTT</div><div class="v">${rtt.toFixed(1)} ms</div></div>
        <div class="metric"><div class="k">Delivered</div><div class="v">${formatBytesMB(Number(p.bytes_delivered || 0))}</div></div>
        <div class="metric"><div class="k">Received</div><div class="v">${formatBytesMB(Number(p.bytes_received || 0))}</div></div>
      </div>
      <div class="meter-group">
        <div class="meter-line">
          <div class="meter-head"><span>Throughput</span><span>${throughput.toFixed(2)} Mbps</span></div>
          <div class="bar-bg"><div class="bar-fg bw-bar" style="width:${bwWidth}%"></div></div>
        </div>
        <div class="meter-line">
          <div class="meter-head"><span>RTT</span><span>${rtt.toFixed(1)} ms</span></div>
          <div class="bar-bg"><div class="bar-fg ${rttClass}" style="width:${rttWidth}%"></div></div>
        </div>
      </div>
    </div>`;
}

function renderNetworkStats(ns) {
  const pathGrid = document.getElementById('pathGrid');
  const eventTimeline = document.getElementById('eventTimeline');
  const netStatus = document.getElementById('netStatus');
  const connState = document.getElementById('connState');
  const connStateSub = document.getElementById('connStateSub');
  const bytesSaved = document.getElementById('bytesSaved');
  const activePath = document.getElementById('activePath');
  const activePathSub = document.getElementById('activePathSub');

  if (!ns || !ns.connections || ns.connections.length === 0) {
    netStatus.textContent = 'No active QUIC connection';
    connState.textContent = 'idle';
    connStateSub.textContent = '연결 없음';
    bytesSaved.textContent = formatBytesMB(ns ? ns.bytes_saved || 0 : 0);
    activePath.textContent = '—';
    activePathSub.textContent = '수신 데이터 없음';
    pathGrid.innerHTML = '<div class="empty">활성 패스 데이터가 없습니다.</div>';
    eventTimeline.innerHTML = '<div class="empty">이벤트 로그가 없습니다.</div>';
    return;
  }

  const c = ns.connections[0];
  connState.textContent = c.state || 'unknown';
  connStateSub.textContent = `last update · ${(ns.timestamp || 0)}`;
  bytesSaved.textContent = formatBytesMB(Number(ns.bytes_saved || 0));
  activePath.textContent = ns.active_path >= 0 ? `Path ${ns.active_path}` : '—';
  activePathSub.textContent = ns.active_path >= 0 ? '현재 주 수신 경로' : '감지되지 않음';
  netStatus.innerHTML = `State: <strong style="color:var(--blue)">${c.state || 'unknown'}</strong> · Saved: <strong>${formatBytesMB(Number(ns.bytes_saved || 0))}</strong>`;

  if (c.paths && c.paths.length > 0) {
    pathGrid.innerHTML = c.paths.map(p => buildPathCard(p, ns)).join('');
  } else {
    pathGrid.innerHTML = '<div class="empty">패스 정보가 아직 없습니다.</div>';
  }

  if (ns.events && ns.events.length > 0) {
    const reversed = [...ns.events].reverse();
    eventTimeline.innerHTML = reversed.map(e => {
      const cls = e.includes('HANDOVER') ? 'event-item handover' : 'event-item';
      return `<div class="${cls}">${e}</div>`;
    }).join('');
  } else {
    eventTimeline.innerHTML = '<div class="empty">핸드오버 또는 활성 경로 변경 이벤트를 기다리는 중입니다.</div>';
  }
}

async function refresh() {
  if (PAGE_VIEW !== 'live') return;
  try {
    const r = await fetch('/stats');
    const d = await r.json();
    document.getElementById('frameCount').textContent = d.frame_count;
    document.getElementById('latestName').textContent = d.latest_name || '—';

    if (prevCount > 0 && d.frame_count > prevCount) {
      fpsSamples.push(d.frame_count - prevCount);
      if (fpsSamples.length > 10) fpsSamples.shift();
    }
    prevCount = d.frame_count;
    const avgFps = fpsSamples.length > 0 ? (fpsSamples.reduce((a, b) => a + b, 0) / fpsSamples.length).toFixed(1) : '—';
    document.getElementById('fps').textContent = avgFps;

    const now = Date.now() / 1000;
    const elapsed = now - (d.latest_mtime || now);
    const statusLine = document.getElementById('statusLine');
    if (d.frame_count === 0 || (!d.has_depth && !d.has_rgb)) {
      statusLine.innerHTML = '<span class="status-warn">waiting for frames</span>';
    } else if (elapsed < 5) {
      statusLine.innerHTML = '<span class="status-live">streaming</span>';
    } else if (elapsed < 30) {
      statusLine.innerHTML = `<span class="status-warn">stalled (${Math.round(elapsed)}s ago)</span>`;
    } else {
      statusLine.innerHTML = `<span class="status-dead">stopped (${Math.round(elapsed)}s ago)</span>`;
    }

    renderNetworkStats(d.network_stats);

    const ts = new Date().getTime();
    const tempImg = new Image();
    tempImg.onload = () => {
      document.getElementById('frameImage').src = tempImg.src;
    };
    tempImg.onerror = () => {};
    tempImg.src = '/frame/' + currentView + '?_=' + ts;
  } catch (e) {
    document.getElementById('statusLine').innerHTML = '<span class="status-dead">connection error</span>';
  }
}

if (PAGE_VIEW === 'live') {
  document.getElementById('runsSection').style.display = 'none';
  document.getElementById('compareSection').style.display = 'none';
  setInterval(refresh, 1000);
  refresh();
} else if (PAGE_VIEW === 'experiments') {
  document.getElementById('liveSection').style.display = 'none';
  document.getElementById('compareSection').style.display = 'none';
  refreshExperiments();
  setInterval(refreshExperiments, 5000);
} else {
  document.getElementById('liveSection').style.display = 'none';
  document.getElementById('runsSection').style.display = 'none';
  refreshCompare();
  setInterval(refreshCompare, 5000);
}
</script>
</body>
</html>
"""


def render_page(view_mode):
    html = HTML_TEMPLATE.replace("__VIEW_MODE__", view_mode)
    html = html.replace("__LIVE_ACTIVE__", "active" if view_mode == "live" else "")
    html = html.replace("__EXPERIMENTS_ACTIVE__", "active" if view_mode == "experiments" else "")
    html = html.replace("__COMPARE_ACTIVE__", "active" if view_mode == "compare" else "")
    return html


class MonitorHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path_only = parsed.path

        if path_only in ["/", "/index.html", "/live"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(render_page("live").encode("utf-8"))
            return

        if path_only == "/experiments":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(render_page("experiments").encode("utf-8"))
            return

        if path_only == "/compare":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(render_page("compare").encode("utf-8"))
            return

        if path_only == "/stats":
            data = get_stats()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        if path_only == "/api/experiments":
            data = list_experiment_runs()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        if path_only == "/api/experiment":
            qs = parse_qs(parsed.query)
            run_id = qs.get("run_id", [""])[0]
            data = get_experiment_detail(run_id)
            if data is None:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"run not found")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        if path_only.startswith("/frame/composite"):
            depth_path, rgb_path, _ = get_latest_pair()
            if depth_path and rgb_path:
                jpeg_data = make_composite_jpeg(depth_path, rgb_path)
                if jpeg_data:
                    self.send_response(200)
                    self.send_header("Content-Type", "image/jpeg")
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(jpeg_data)
                    return
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"no frames yet")
            return

        if path_only.startswith("/frame/rgb"):
            _, rgb_path, _ = get_latest_pair()
            if rgb_path and os.path.isfile(rgb_path):
                self.send_response(200)
                self.send_header("Content-Type", "image/jpeg")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                with open(rgb_path, "rb") as f:
                    self.wfile.write(f.read())
                return
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"no rgb frames yet")
            return

        if path_only.startswith("/frame/depth"):
            depth_path, _, _ = get_latest_pair()
            if depth_path and os.path.isfile(depth_path):
                if HAS_PIL:
                    img = Image.open(depth_path)
                    if img.mode in ("I", "I;16", "I;16L", "I;16B"):
                        arr = np.array(img, dtype=np.float32)
                        jet_rgb = _normalize_depth_to_jet(arr)
                        mask = arr > 0
                        bg = np.full((*arr.shape, 3), 36, dtype=np.uint8)
                        bg[mask] = jet_rgb[mask]
                        out = Image.fromarray(bg, "RGB")
                        buf = io.BytesIO()
                        out.save(buf, format="JPEG", quality=85)
                        self.send_response(200)
                        self.send_header("Content-Type", "image/jpeg")
                        self.send_header("Cache-Control", "no-store")
                        self.end_headers()
                        self.wfile.write(buf.getvalue())
                        return
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                with open(depth_path, "rb") as f:
                    self.wfile.write(f.read())
                return
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"no depth frames yet")
            return

        if path_only.startswith("/frame/latest"):
            self.send_response(302)
            self.send_header("Location", "/frame/composite")
            self.end_headers()
            return

        if path_only.startswith("/frames/"):
            rel = path_only[8:]
            filepath = FRAMES_DIR / rel
            if filepath.is_file():
                ext = os.path.splitext(rel)[1].lower()
                ctype = "image/jpeg" if ext in (".jpg", ".jpeg") else "image/png" if ext == ".png" else "application/octet-stream"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.end_headers()
                with open(filepath, "rb") as f:
                    self.wfile.write(f.read())
                return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"404 not found")

    def log_message(self, format, *args):
        pass


def main():
    FRAMES_DIR.mkdir(parents=True, exist_ok=True)
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), MonitorHandler)
    print("[MONITOR] Experiment console started")
    print(f"    URL:      http://0.0.0.0:{PORT}/")
    print(f"    Frames:   {FRAMES_DIR}")
    print(f"[MONITOR] Open in browser: http://192.168.0.80:{PORT}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    main()
