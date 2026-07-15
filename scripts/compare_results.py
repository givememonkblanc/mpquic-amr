#!/usr/bin/env python3
"""
compare_results.py — summarize scheduler runs (replay suite OR repeated real
drives). One row per run; --agg groups repeats by scheduler → mean ± std (CI).

Reads *_events.csv (fixed outage_us + switch_count columns) from a dir. The row
label is the filename stem (e.g. "rssi_run3" → mode "rssi", run "run3").

Usage:
  ./compare_results.py <dir>            # one row per run
  ./compare_results.py <dir> --agg      # mean ± std per scheduler across repeats
  ./compare_results.py <dir> --server 192.168.0.38   # filter by server tag
"""
import argparse, csv, glob, os, re, math

def summarize(events_csv):
    rows = [r for r in csv.DictReader(open(events_csv))
            if r.get("t_us", "").strip().isdigit()]   # skip trailing "# SUMMARY:" line
    if not rows:
        return None
    for r in rows:
        for k in ("t_us", "path_i", "frame_bytes", "outage_us", "switch_count"):
            r[k] = int(r[k])
    dur = (rows[-1]["t_us"] - rows[0]["t_us"]) / 1e6
    tot = sum(r["frame_bytes"] for r in rows) or 1
    wifi = sum(r["frame_bytes"] for r in rows if r["path_i"] == 0)
    fiveg = sum(r["frame_bytes"] for r in rows if r["path_i"] == 1)
    outs = [r["outage_us"] for r in rows if r["outage_us"] > 0]
    out_s = sum(outs) / 1e6
    return dict(frames=len(rows), MB=tot/1e6, dur_s=dur,
                tput=tot*8/1e6/dur if dur else 0,
                wifi_pct=100*wifi/tot, fiveg_pct=100*fiveg/tot,
                switches=rows[-1]["switch_count"], outages=len(outs),
                outage_s=out_s, avail_pct=100*(1-out_s/dur) if dur else 0)

def mode_of(stem):
    m = re.match(r"([a-z]+)", stem)
    return m.group(1) if m else stem

def mean_std(xs):
    n = len(xs)
    if n == 0: return (0.0, 0.0)
    mu = sum(xs)/n
    sd = math.sqrt(sum((x-mu)**2 for x in xs)/n) if n > 1 else 0.0
    return (mu, sd)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--server", default=None)
    ap.add_argument("--agg", action="store_true", help="mean±std per scheduler")
    a = ap.parse_args()
    pat = f"*_{a.server}_*events.csv" if a.server else "*_events.csv"
    files = sorted(glob.glob(os.path.join(a.dir, pat)))
    if not files:
        print("no *_events.csv in", a.dir); return

    runs = []
    for f in files:
        s = summarize(f)
        if s:
            stem = os.path.basename(f).replace("_events.csv", "")
            runs.append((stem, s))

    if a.agg:
        by = {}
        for stem, s in runs:
            by.setdefault(mode_of(stem), []).append(s)
        hdr = f"{'mode':<9}{'n':>3}{'tput(Mb)':>18}{'WiFi%':>13}{'switch':>13}{'outage(s)':>15}{'avail%':>13}"
        print(hdr); print("-"*len(hdr))
        for mode in sorted(by):
            ss = by[mode]
            def ms(key, fmt="{:.2f}±{:.2f}"):
                mu, sd = mean_std([x[key] for x in ss]); return fmt.format(mu, sd)
            print(f"{mode:<9}{len(ss):>3}{ms('tput'):>18}{ms('wifi_pct','{:.0f}±{:.0f}'):>13}"
                  f"{ms('switches','{:.0f}±{:.0f}'):>13}{ms('outage_s','{:.1f}±{:.1f}'):>15}"
                  f"{ms('avail_pct','{:.1f}±{:.1f}'):>13}")
        print("\n(mean ± std across repeats)")
    else:
        hdr = f"{'run':<16}{'tput':>9}{'WiFi%':>7}{'5G%':>6}{'switch':>7}{'outage':>8}{'avail%':>8}{'dur':>7}"
        print(hdr); print("-"*len(hdr))
        for stem, s in runs:
            print(f"{stem:<16}{s['tput']:>6.2f}Mb{s['wifi_pct']:>6.0f}{s['fiveg_pct']:>6.0f}"
                  f"{s['switches']:>7}{s['outage_s']:>6.1f}s{s['avail_pct']:>7.1f}{s['dur_s']:>6.0f}s")
        print(f"\n{len(runs)} runs. --agg for per-scheduler mean±std.")

if __name__ == "__main__":
    main()
