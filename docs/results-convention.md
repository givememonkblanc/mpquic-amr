# results/ 규칙 (experiment output convention)

실험 결과가 규칙 없이 쌓여 "뭐가 뭔지" 알기 어려워서 정한 규칙. `results/`는 git에서 제외
(gitignore)되지만, **구조·명명·파일 스키마는 이 문서가 기준**이다. 스크립트도 이 규칙을 따른다.

---

## 1. 최상위 구조

```
results/
├── experiment_runs/   ← 모든 실험 런. 런 하나 = 디렉토리 하나 (§2 명명)
├── qlogs_client/      ← 스케줄러 비교용 qlog CSV 모음 (mode별, run_all_schedulers가 수집)
├── hls/               ← 라이브 HLS 임시 출력 (run_hls.sh; 매 실행 시 삭제됨. 영구 아님)
├── captures/          ← *.pcap 패킷 캡처
└── _archive/          ← 옛 dev 테스트·잔재 (보관용, 안 봐도 되는 것)
```

## 2. 런 명명 규칙

```
<YYYYMMDD-HHMMSS>_<kind>[_<detail>]
```

- **시각 접두사 필수** — 정렬·추적이 되도록. 예 `20260713-190243`.
- **kind** (한 단어): `matrix` · `drive` · `handover` · `degradation` · `steady` · `stream` · `smoke`
- detail은 선택 (예 `_phonemoved`, `_proactive`).

| kind | 뜻 |
|---|---|
| `matrix` | run_matrix.sh — scenario×mode×rep 자동 스윕 (§4 하위구조) |
| `drive` | 수동 주행 중 스트리밍 (긴 실주행, proactive/pqi 등) |
| `handover` | Wi-Fi 절단→재접속 단발 핸드오버 테스트 |
| `degradation` | iptables 손실 램프 (proactive 감지) 단발 |
| `steady` | 절단 없는 정상 스트리밍 |
| `stream`/`smoke` | 프리뷰·기능 스모크 (버려도 됨) |

예: `20260713-190243_drive_proactive`, `20260713-164811_matrix`, `20260713-095150_handover`.

## 3. 런 내부 표준 파일

런 디렉토리 안은 **항상 이 이름**을 쓴다 (기존엔 client.log/edge_client.log/drive_client.log 등 제각각이었음 → `edge_client.log`로 통일):

| 파일 | 내용 | 항상? |
|---|---|---|
| `meta.json` | 런 메타데이터 (§5) | ✅ |
| `server.log` | 수신 서버(server_recv) 로그 | ✅ |
| `edge_client.log` | orin 클라 로그 (PQI/PATH-SELECT/RSSI/switch) | ✅ |
| `events.csv` | per-frame qlog (§4 스키마) | ✅ |
| `snap.csv` | per-snapshot 경로 health (§4 스키마) | ✅ |
| `driver.log` | 실험 드라이버 스크립트 로그 | 매트릭스 |
| `frames/` | 저장된 프레임 (`SVR_SAVE_FRAMES=1`일 때만; 스트리밍 런은 없음) | 선택 |
| `preview.mp4` | 프리뷰 녹화 | 선택 |

## 4. 매트릭스 하위 구조 + CSV 스키마

**매트릭스 런**은 rep별 서브디렉토리 + 요약:
```
<matrix_id>/
├── matrix_summary.tsv
├── steady_rssi_rep1/      ← <scenario>_<mode>_rep<N>/  (내부는 §3 표준 파일)
├── handover_rssi_rep1/
└── degradation_pqi_rep2/
```

**`events.csv`** (per-frame, 클라 qlogger):
```
t_us, path_i, frame_bytes, rtt_us, choice_reason, switch_count, outage_us, cum_bytes
```
**`snap.csv`** (per-snapshot, 경로 상태):
```
t_us, path_i, verified, demoted, healthy, srtt_us, loss_bytes, sent_bytes, in_flight
```
**`matrix_summary.tsv`**:
```
scenario  mode  rep  status  frames_rx  notes
```

### `choice_reason` 값 (스케줄러가 그 프레임을 왜 그 경로로 보냈나)
| 값 | 의미 |
|---|---|
| `primary_only` | 주경로만 쓸 만함 |
| `debounce_hold` | 스위치 억제 창(anti-ping-pong) 중 유지 |
| `degrade_failover` | 주경로 열화 감지 → 백업으로 (reactive) |
| `rssi_preemptive_handover` | **RSSI 저하 선제 감지 → 죽기 전 백업으로 (proactive, 논문 핵심)** |
| `rssi_recover_primary` / `stable_failback` | 주경로 회복 → 복귀 |
| `both_unusable_hold_*` | 양쪽 다 불가 → 마지막 경로 유지 (아웃티지) |

`path_i`: **0 = Wi-Fi(주), 1 = 5G 핫스팟(백업)**.

## 5. `meta.json` (런마다 1개 — 이게 "이 런이 뭔지"를 설명)

```json
{
  "kind": "drive", "scenario": "proactive", "mode": "rssi", "reps": 1,
  "start_wall": "2026-07-13 19:02:43", "git_commit": "7d1780c",
  "server_ip": "192.168.0.38", "edge": "orin (jetson-desktop)",
  "notes": "수동 주행, 백업 5G 재배치",
  "summary": {"frames_rx": 2369, "MB": 73.5, "switches": 6, "proactive": 1, "outcome": "OK"}
}
```

## 6. 현재 런 인덱스 (2026-07-13 기준)

| 종류 | 개수 | 크기 | 대표 |
|---|---|---|---|
| record(7/12) | 5 | 945 MB | 20260712-rec-manual3, 20260712-rec-manual2, 20260712-rec-manual |
| dev-cruft(6월) | 20 | 451 MB | frames_out_degrad_2, frames_out_degrad_3, frames_out_failover_hotspot |
| handover | 3 | 7 MB | handover-phonemoved2-163848, handover-verify-095150, handover-phonemoved-163624 |
| drive | 2 | 3 MB | drive-proactive, drive-pqi |
| smoke/검증 | 3 | 1 MB | smoke2-093949, hs-reliability-164808, smoke-verify-093345 |
| matrix | 5 | 1 MB | preflight-163250, smoke1, preflight2-164121 |
| 기타 | 1 | 0 MB | preview_debug |

합계: 39개 런, 1.41 GB

## 7. 정리 제안

- **6월 `frames_out_*` 20개(451 MB)** = dev 테스트 잔재 → `results/_archive/`로 이동하거나 삭제.
- **7/12 녹화 5개(945 MB)** = 실제 녹화. 남길 것만 골라 유지, 나머지 archive.
- 내 검증 스모크(`smoke*`, `hs-reliability*`, `*-verify`) = 버려도 됨.
- 앞으로 새 런은 §2 명명 + §3 파일 + §5 meta.json 을 따르도록 스크립트 갱신.
