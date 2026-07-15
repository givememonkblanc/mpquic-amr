#!/usr/bin/env python3
"""
rx_analyze.py — receiver-side goodput + interruption from the server RX qlog
(MPQUIC_RX_QLOG: t_us,type,bytes per DELIVERED frame). This is the ground truth
"ack" view: only frames that actually arrived count, and gaps between arrivals
are real stream interruptions (video freezes) — unlike the client send-side qlog
which over-counts frames pushed into a dead path during a coverage gap.

  ./rx_analyze.py <rxqlog.csv> [--gap-ms 500]
"""
import argparse, csv, sys

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rxqlog")
    ap.add_argument("--gap-ms", type=float, default=500.0,
                    help="arrival gap over this = an interruption (default 500ms)")
    a = ap.parse_args()
    rows = [r for r in csv.DictReader(open(a.rxqlog)) if r.get("t_us", "").strip().isdigit()]
    if len(rows) < 2:
        print("empty/short rxqlog"); return
    t = [int(r["t_us"]) for r in rows]
    b = [int(r["bytes"]) for r in rows]
    dur = (t[-1] - t[0]) / 1e6
    tot = sum(b)
    gaps = [(t[i] - t[i-1]) / 1e6 for i in range(1, len(t))]
    thr = a.gap_ms / 1000.0
    interruptions = [g for g in gaps if g > thr]
    # per type
    bytype = {}
    for r in rows:
        bytype.setdefault(r["type"], [0, 0]); bytype[r["type"]][0] += 1
        bytype[r["type"]][1] += int(r["bytes"])
    print(f"수신 프레임: {len(rows)}   지속: {dur:.1f}s   수신량: {tot/1e6:.2f} MB")
    print(f"goodput(수신 기준): {tot*8/1e6/dur:.2f} Mbps")
    for ty, (n, bb) in sorted(bytype.items()):
        print(f"  type={ty}: {n}프레임 {bb/1e6:.2f}MB")
    down = sum(interruptions)
    print(f"끊김(>{a.gap_ms:.0f}ms 도착공백): {len(interruptions)}건  "
          f"합계 {down:.2f}s  최대 {max(interruptions) if interruptions else 0:.2f}s")
    print(f"수신 가용률: {100*(1-down/dur):.1f}%   평균 프레임간격: {sum(gaps)/len(gaps)*1000:.0f}ms")

if __name__ == "__main__":
    main()
