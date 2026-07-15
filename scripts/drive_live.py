#!/usr/bin/env python3
"""drive_live.py — read-only live health monitor for a running drive/stream.

Serves a self-refreshing page that watches the receiver's stats.json (written
~2x/sec) plus drive_events.csv, so you can tell at a glance whether the drive is
actually streaming right now. Touches nothing the experiment uses (read-only).

  python3 scripts/drive_live.py --run drive-proactive --port 8145
"""
import argparse, json, os, time, http.server, socketserver
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--run", default="drive-proactive")
ap.add_argument("--port", type=int, default=8145)
args = ap.parse_args()

ROOT = Path(__file__).resolve().parent.parent
RUN = ROOT / "results" / "experiment_runs" / args.run
STATS = RUN / "frames" / "stats.json"
EVENTS = RUN / "drive_events.csv"


def tail_events(n=1):
    try:
        with open(EVENTS, "rb") as f:
            f.seek(0, 2); size = f.tell(); back = min(size, 8192)
            f.seek(size - back); lines = f.read().decode("utf-8", "replace").splitlines()
        return [l for l in lines if l and l[0].isdigit()][-n:]
    except Exception:
        return []


def health():
    now = time.time()
    h = {"ok": False, "age": None, "frames": None, "active_path": None,
         "paths": [], "switch_count": None, "cum_mb": None, "events": [], "ts": now}
    # server stats.json (freshness = is the receiver still writing?)
    try:
        st = os.stat(STATS)
        h["age"] = round(now - st.st_mtime, 1)
        s = json.loads(STATS.read_text())
        h["frames"] = s.get("frame_count")
        h["active_path"] = s.get("active_path")
        h["events"] = s.get("events", [])[-4:]
        for c in s.get("connections", []):
            for p in c.get("paths", []):
                h["paths"].append({
                    "id": p.get("id"), "rtt_ms": p.get("rtt_ms"),
                    "mbps": p.get("throughput_mbps"), "verified": p.get("verified"),
                    "local": p.get("local_ip"), "remote": p.get("remote_ip")})
        # streaming considered live if stats.json was written within 3 s
        h["ok"] = h["age"] is not None and h["age"] <= 3.0
    except Exception as e:
        h["err"] = str(e)
    # client-side scheduler tail
    row = tail_events(1)
    if row:
        try:
            c = row[0].split(",")
            h["switch_count"] = int(c[5]); h["cum_mb"] = round(int(c[7]) / 1e6, 1)
            h["last_reason"] = c[4]; h["last_rtt_ms"] = round(int(c[3]) / 1000, 1)
            h["last_path"] = int(c[1])
        except Exception:
            pass
    return h


PAGE = """<!doctype html><html lang=ko><head><meta charset=utf-8>
<title>드라이브 라이브 모니터</title><meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{--bg:#0e1117;--sf:#161b24;--bd:#29313f;--tx:#e6eaf1;--dim:#9aa4b7;--faint:#6b7488;
--ok:#3ddc84;--bad:#ff6f61;--wifi:#3b82f6;--hot:#ea580c;--ac:#2dd4bf;
--mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;--sans:-apple-system,"Segoe UI",Roboto,"Malgun Gothic",sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font-family:var(--sans);font-size:15px}
.w{max-width:840px;margin:0 auto;padding:26px 20px 60px}
.status{display:flex;align-items:center;gap:12px;padding:16px 20px;border-radius:14px;border:1px solid var(--bd);background:var(--sf);margin-bottom:18px}
.dot{width:14px;height:14px;border-radius:50%;flex:none;box-shadow:0 0 0 0 currentColor;animation:pulse 1.6s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 currentColor}70%{box-shadow:0 0 0 9px transparent}100%{box-shadow:0 0 0 0 transparent}}
.status.live{color:var(--ok)}.status.stall{color:var(--bad);animation:none}
.status .dot.stall{animation:none}
.status b{font-size:19px}.status .sub{color:var(--dim);font-size:13px;font-family:var(--mono);margin-left:auto}
h1{font-size:16px;margin:0 0 3px;font-weight:700}.run{font-family:var(--mono);font-size:12px;color:var(--faint)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:18px 0}
.t{background:var(--sf);border:1px solid var(--bd);border-radius:12px;padding:14px 16px}
.t .n{font-size:26px;font-weight:700;font-family:var(--mono);font-variant-numeric:tabular-nums;line-height:1}
.t .u{font-size:13px;color:var(--dim)} .t .l{font-size:12px;color:var(--dim);margin-top:6px}
.t.wifi .n{color:var(--wifi)} .t.hot .n{color:var(--hot)}
.spark{height:56px;width:100%;display:block;margin-top:6px}
.paths{margin-top:6px}
.prow{display:flex;align-items:center;gap:10px;font-family:var(--mono);font-size:13px;padding:9px 12px;border:1px solid var(--bd);border-radius:10px;background:var(--sf);margin-bottom:8px}
.chip{font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px}
.chip.v{color:var(--ok);background:#3ddc8416}.chip.a{color:var(--ac);background:#2dd4bf16}
.ev{font-family:var(--mono);font-size:12px;color:var(--dim);background:var(--sf);border:1px solid var(--bd);border-radius:10px;padding:10px 13px;margin-top:14px}
.foot{margin-top:20px;font-family:var(--mono);font-size:11px;color:var(--faint);text-align:center}
</style></head><body><div class=w>
<h1>드라이브 라이브 모니터</h1><div class=run id=run></div>
<div class="status" id=st><span class="dot" id=dot></span><b id=stlabel>연결 중…</b><span class=sub id=age></span></div>
<div class=tiles id=tiles></div>
<svg class=spark id=spark viewBox="0 0 800 56" preserveAspectRatio=none></svg>
<div class=paths id=paths></div>
<div class=ev id=ev></div>
<div class=foot id=foot>read-only · stats.json 폴링</div>
</div>
<script>
var rttHist=[];
function fmt(v,d){return v==null?'—':(typeof v==='number'?v.toFixed(d==null?0:d):v)}
async function tick(){
  var h; try{ h=await (await fetch('/health',{cache:'no-store'})).json(); }catch(e){ setStall('서버 응답 없음'); return; }
  document.getElementById('run').textContent='run: '+RUN+'  ·  path 0 = Wi-Fi, path 1 = 5G hotspot';
  var st=document.getElementById('st'), dot=document.getElementById('dot');
  if(h.ok){ st.className='status live'; dot.className='dot';
    document.getElementById('stlabel').textContent='● 스트리밍 정상 (LIVE)'; }
  else { setStall(h.age==null?'stats.json 없음':('정체 — '+h.age+'s 갱신 없음')); }
  document.getElementById('age').textContent='updated '+fmt(h.age,1)+'s ago';
  // active path throughput/rtt from stats paths
  var ap=(h.paths||[]).find(function(p){return p.id===h.active_path})||{};
  var pcls=h.active_path===1?'hot':'wifi';
  var tiles=[
    {n:fmt(ap.mbps,1),u:' Mbps',l:'현재 처리량 (active)'},
    {n:fmt(ap.rtt_ms,1),u:' ms',l:'RTT (active)',cls:pcls},
    {n:h.active_path===1?'5G':'Wi-Fi',u:'',l:'활성 경로 (path '+fmt(h.active_path)+')',cls:pcls},
    {n:fmt((h.paths||[]).reduce(function(a,p){return a+(p.mbps||0)},0),1),u:' Mbps',l:'총 처리량 (경로 합)'},
    {n:fmt(h.switch_count),u:'',l:'경로 스위치'},
    {n:fmt(h.cum_mb,1),u:' MB',l:'누적 전송'}
  ];
  document.getElementById('tiles').innerHTML=tiles.map(function(t){return '<div class="t '+(t.cls||'')+'"><div class=n>'+t.n+'<span class=u>'+t.u+'</span></div><div class=l>'+t.l+'</div></div>'}).join('');
  // paths
  document.getElementById('paths').innerHTML=(h.paths||[]).map(function(p){
    return '<div class=prow><b>path '+p.id+'</b>'+(p.id===h.active_path?'<span class="chip a">active</span>':'')+
      (p.verified?'<span class="chip v">verified</span>':'')+
      '<span style="color:var(--faint)">'+(p.local||'')+' ↔ '+(p.remote||'')+'</span>'+
      '<span style="margin-left:auto">'+fmt(p.rtt_ms,1)+'ms · '+fmt(p.mbps,1)+'Mbps</span></div>';
  }).join('')||'<div class=prow style="color:var(--faint)">경로 없음</div>';
  // rtt sparkline (accumulate active-path rtt)
  if(ap.rtt_ms!=null){rttHist.push(ap.rtt_ms); if(rttHist.length>80)rttHist.shift();}
  drawSpark();
  // events
  var evs=(h.events||[]);
  document.getElementById('ev').innerHTML='<div style="color:var(--faint);margin-bottom:5px">서버 이벤트 · 마지막 결정: '+(h.last_reason||'—')+'</div>'+
    (evs.length?evs.map(function(e){return '<div>'+e+'</div>'}).join(''):'<div>—</div>');
  document.getElementById('foot').textContent='read-only · '+new Date().toLocaleTimeString()+' · stats.json 폴링 1.5s';
}
function setStall(msg){var st=document.getElementById('st');st.className='status stall';
  document.getElementById('dot').className='dot stall';document.getElementById('stlabel').textContent='● '+msg;}
function drawSpark(){
  var svg=document.getElementById('spark');if(rttHist.length<2){svg.innerHTML='';return;}
  var mx=Math.max.apply(null,rttHist)*1.1||1,W=800,H=56;
  var d=rttHist.map(function(v,i){return (i?'L':'M')+(i/(rttHist.length-1)*W).toFixed(1)+' '+(H-v/mx*H).toFixed(1)}).join(' ');
  svg.innerHTML='<path d="'+d+'" fill=none stroke="var(--ac)" stroke-width=1.6/>'+
    '<text x=4 y=11 style="font:10px var(--mono);fill:var(--faint)">RTT '+rttHist[rttHist.length-1].toFixed(0)+'ms (active path)</text>';
}
tick(); setInterval(tick,1500);
</script></body></html>"""


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/health"):
            body = json.dumps(health()).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(body)
        else:
            body = PAGE.replace("RUN", json.dumps(args.run)).encode()
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers(); self.wfile.write(body)


socketserver.ThreadingTCPServer.allow_reuse_address = True
with socketserver.ThreadingTCPServer(("0.0.0.0", args.port), H) as srv:
    print(f"drive_live on :{args.port} watching {RUN}")
    srv.serve_forever()
