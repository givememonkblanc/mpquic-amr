# COMCOM-D-26-01559 리뷰어 지적 체크리스트 & 반영 현황

기준일 2026-07-13. 대상 원고 `Com-0420_레퍼런스 수정 및 검토 완료본.docx`.

## 상태 범례
| 기호 | 의미 |
|---|---|
| ✅ | 반영 완료 (원고/코드에 실제 존재) |
| 🟡 | 부분 — 코드·시스템은 완료됐으나 **원고 텍스트 미반영** |
| 📝 | 계획 확정 (`revision_plan.md`에 매핑), **원고 미편집** |
| 🔬 | 실험 수치 대기 — N=10 매트릭스 완료 후 채움 |
| ⛔ | 블록됨 (선행 작업 필요) |

> **현 시점 핵심**: `Com-0420_revised.docx`는 아직 생성 전 → **논문 본문에 반영 완료(✅)된 항목은 없음.** 코드/시스템은 여러 건 완료(🟡). 나머지는 계획(📝) 또는 실험 대기(🔬).

---

## Reviewer #1

| ID | 지적 요약 | 유형 | 요구 조치 | 상태 | 근거/위치 |
|---|---|---|---|---|---|
| R1.1 | MP-QUIC은 표준 아님, draft(현 v21) 명시 안 함 | Paper | draft 상태·표준화 이력 명시 | 📝 | plan §2.2 |
| R1.2 | "표준 MP 스케줄러 실패" — 스케줄러는 impl-specific(draft §5.5) | Paper | default/reference로 리워딩, §5.5 인용 | 📝 | plan §2.2 |
| R1.3 | MP-QUIC 스케줄러 관련연구 부재 | Paper | 신규 소절 "MP-QUIC Schedulers" 서베이 | 📝 | plan §2.2 |
| R1.4 | QUIC connection migration(RFC9000 §9) 미제시 | Paper | migration/path validation 문단 + 차이 | 📝 | plan §2.2 |
| R1.5 | Fig.3 구성요소 상세·구현 여부 불명 | Paper+Code | 3모듈→코드 1:1 매핑, 실구현 명시 | 🟡 | 코드 존재(`client_loop.c`), 원고 미반영 |
| R1.6 | min-max 정규화 수식 부재 | Paper | 정규화 3식 명시+번호 | 📝 | plan §3.3 (EQ) |
| R1.7 | PQI 정의식 부재 | Paper | `PQI=100·(1−C)` 명시 | 📝 | plan §3.3 (EQ) |
| R1.8 | path probing 전략 정의 부재 | Paper | per-path 지표 취득법 문서화 | 🟡 | 코드 구현됨, 원고 미반영 |
| R1.9 | 비디오 프레임 경계 인지 방법 | Paper | 9B `[MPQ1][type][len]` 프레이밍 기술 | 🟡 | 코드 구현됨(`client_loop.c`), 원고 미반영 |
| R1.10 | default·SP-QUIC+migration 베이스라인, SP-QUIC 5G 불공정 | Code+Eval | 베이스라인 추가 + spquic가 5G로 migration | 🟡⛔🔬 | 코드 수정·빌드 완료 / 검증 ⛔(ssh_edge 버그) / 수치 🔬 |

## Reviewer #2

| ID | 지적 요약 | 유형 | 요구 조치 | 상태 | 근거/위치 |
|---|---|---|---|---|---|
| R2.1 | §2.1 "question"→"matter" | Paper | 단어 교체 | 📝 | plan §A |
| R2.2 | QUIC을 TCP 경쟁자/우월로 프레이밍 | Paper | 균형 trade-off 서술 | 📝 | plan §2.2 |
| R2.3 | 양 링크 동시활성=엄밀히 handover 아님; 문제정의 모호 | Paper | soft-handover 용어정의, 문제 일관화 | 📝 | plan §2.2/§1 |
| R2.4 | 왜 5G 빠른가·HoL(QUIC은 본질 회피) | Paper | 경로간 스케줄링/재정렬로 정정 | 📝 | plan §2.2 |
| R2.5 | 3GPP N3IWF/ATSSS 고려 | Paper | N3IWF 소개 후 전송계층 대비 | 📝 | plan §1/§3.1 |
| R2.6 | Fig.5 어떤 앱? total delay 정의? | Paper | 워크로드=비디오스트림, 지연 정의 | 📝 | plan §4 |
| R2.7 | "cross traffic" 정의 | Paper+Eval | iptables 손실램프+iperf3 정의 | 🟡🔬 | 하네스에 기구 존재, 정의·수치 대기 |
| R2.8 | "no traffic no delay?"; 핸드오버 몇 번? | Eval | 시나리오 명확화 + 이벤트 수 보고 | 🔬 | 통계 파이프라인 |
| R2.9 | 50/150Mbps 현실성; 실제 AMR 레이트↓ | Paper+Eval | 레이트 정당화(다중카메라 실측) | 🟡🔬 | 오늘 ~20Mbps 실측, 정당화 텍스트 대기 |
| R2.10 | Fig.8 핸드오버 5.5s 너무 김 | Code+Eval | 신 히스테리시스로 재측정·설명 | 🟡🔬 | 코드 선제화 완료, 클린 수치 대기 |

## Reviewer #3

| ID | 지적 요약 | 유형 | 요구 조치 | 상태 | 근거/위치 |
|---|---|---|---|---|---|
| R3.1 | 무엇이 novel인가 (지표/추세/히스테리시스/통합) | Paper | 기여 정밀화 (RSSI-main 확정) | 🟡 | 방향 확정, 원고 미반영 |
| R3.2 | "virtually eliminates outages" 과장 | Paper | 측정 기반 완화 | 📝🔬 | plan; 수치 대기 |
| R3.3 | α,β,γ,T_deg,Δ,T_stable,λ,W 미기재 | Code+Paper | 파라미터 표 + 동기화 | 🟡 | `pqi_parameters.md` 존재(오늘 오버홀 반영 필요), 원고 표 미작성 |
| R3.4 | PQI 이득 분리 안 됨; 표준 MP-QUIC 비교 | Code+Eval | 동일 스택 baseline 비교 | 🟡🔬 | 4모드 baseline 코드 존재, 비교 수치 대기 |
| R3.5 | 어떤 impl/어떻게 수정/어느 draft/PQI 어디 | Paper | 구현 명세 (C picoquic draft-20) | 🟡 | 확정(DEC-2), 원고 미반영 |
| R3.6 | 실이동 vs 에뮬; AP배치·속도·run수·5G종류·절단시간 | Paper+Eval | testbed 정직 상술 | 📝🔬 | plan §4.1; 파라미터 일부 매트릭스 |
| R3.7 | 70ms hesitation = reactive이지 proactive 아님 | Paper+Code | proactive(RSSI추세) vs reactive 구분 | 🟡🔬 | 코드 선제화+주행증거 확보, 원고·클린수치 대기 |
| R3.8 | 반복수·평균·분산/CI·유의성 | Eval | N=10, mean±95%CI, 유의성 | 🔬 | 통계 파이프라인(Task#6) |
| R3.9 | 왜 MP-QUIC 정상 처리량 < SP-QUIC | Eval | 원인 규명 or 수정 | 🔬 | 스모크상 동등 관측, 매트릭스 재측정 |
| R3.10 | Wi-Fi 표기 불일치·저해상 figure·수식 번호 | Paper | 표기통일·수식번호·figure재생성 | 📝 | plan §A/전역, figure 별도 |

---

## 집계 (30개 코멘트)

| 상태 | 개수 | 항목 |
|---|---|---|
| ✅ 반영완료 | **0** | — |
| 🟡 코드완료·원고미반영 | 11 | R1.5, R1.8, R1.9, R1.10, R2.7, R2.9, R2.10, R3.1, R3.3, R3.4, R3.5, R3.7 |
| 📝 계획확정·원고미편집 | 11 | R1.1–R1.4, R1.6, R1.7, R2.1–R2.6, R3.2, R3.6, R3.10 (일부중복) |
| 🔬 실험수치 대기 | 9 | R1.10, R2.7, R2.8, R2.9, R2.10, R3.2, R3.4, R3.8, R3.9 |
| ⛔ 블록 | 1 | R1.10 검증(ssh_edge 버그 선수정 필요) |

**한 줄 요약**: 계획·코드는 상당히 진척(🟡 11건), **원고 본문 반영은 0** (편집 미착수). 다음 액션 = ① `revised.docx` 텍스트 패스(📝/🟡 → ✅), ② N=10 매트릭스로 🔬 해소.
