# COMCOM-D-26-01559 — 원고 수정 계획

대상 원고: `Com-0420_레퍼런스 수정 및 검토 완료본.docx` (199 문단 / 2 표 / OMML 수식 문단 75–86)
산출물: `paper_revision/Com-0420_revised.docx` (python-docx로 in-place 편집, 서식 보존)

편집 분류 태그
- **[TXT]** 지금 텍스트만으로 완결 가능 (용어·정의·프레이밍·관련연구·구현명세)
- **[EQ]** 수식 추가/번호 (OMML 편집)
- **[NUM]** 새 실험 수치 필요 → N=10 매트릭스 완료 후. 원고엔 `【NUM: …】` 플레이스홀더로 자리표시
- **[DEC]** 유저 결정 필요 (아래 §0)

---

## §0. 확정된 방향 (2026-07-13 유저 결정)

- **DEC-1 = RSSI-main / PQI-ablation** ✔ 확정.
  메인 방법론 = **RSSI-aware proactive handover**. PQI(정규화 RTT/loss/BW cost)는 기저 전송-품질 지표이며, **RSSI penalty + RSSI-추세 선제 핸드오버 + RSSI-driven failback**을 얹은 것이 제안 방식(`rssi` 모드). 순수 transport-only PQI(`pqi` 모드)는 **ablation**으로 격하 → RSSI가 더하는 선제성(proactivity)을 분리 입증.
  - 파급: **초록·기여·§3 제목·§4 결과 프레이밍 재작성**. Title은 유지 가능("Seamless Handover"), 단 기여문에서 "RSSI-aware proactive"가 헤드라인.
  - 보너스: 이 프레이밍이 **R3.7(proactive vs reactive)**을 자연 해결 — RSSI-추세=선제, 순수 PQI/transport=사후. ablation이 **R3.4(이득 분리)**도 충족.
- **DEC-2 = C picoquic 스택** ✔ 확정. picoquic 1.1.50.3 + draft-ietf-quic-multipath-20. PQI/스케줄러 = `client/client_loop.c`. Go(quic-go)는 초기 프로토타입으로 1줄만.
- **DEC-3 = draft-20 본문 통일**, 관련연구에서 draft-21(2026-03 최신) 등장 각주. (참고문헌[12]은 draft-21.)

### 기여문 재작성안 (§1, RSSI-main 반영)
1. A **handover-adaptive MP-QUIC** transport for AMR Wi-Fi/5G, built on a persistent make-before-break dual-path state (draft-20, picoquic).
2. An **RSSI-aware proactive path-quality scheme**: a normalized multi-metric **PQI** cost (RTT/loss/BW, min-max + EWMA + hysteresis FSM) **augmented with a Wi-Fi RSSI signal** that triggers **preemptive** handover *before* transport metrics degrade, plus RSSI-driven failback.
3. Real-testbed evaluation with **same-stack baselines** (transport-only PQI ablation, minRTT-default, SP-QUIC+migration) and **N-repetition statistics**, showing reduced handover outage/latency without steady-state throughput loss.

---

## §1. Reviewer #1 대응

| ID | 코멘트 | 위치(문단) | 조치 | 태그 |
|---|---|---|---|---|
| R1.1 | MP-QUIC이 표준 아님, draft 상태(현 v21) 명시 | §2.2 QUIC and MP-QUIC (37–43) | "MP-QUIC은 IETF **draft**(draft-ietf-quic-multipath, 최신 v21 2026-03; 2017년 이래 표준화 부침)" 한 문장 추가 | TXT |
| R1.2 | "표준 MP 스케줄러가 실패한다" — 스케줄러는 구현 특정(draft §5.5) | §2.2 마지막 문단(43) | "the **default/reference** scheduler is implementation-specific (draft §5.5); we propose a specific handover-aware scheduler"로 리워딩 | TXT |
| R1.3 | MP-QUIC 스케줄러 관련연구 부재 | §2.2 뒤 새 소절 | **새 소절 "MP-QUIC Schedulers"** 추가: minRTT/RR, ECF, BLEST, Peekaboo, RL 기반, MAMS[13], stream-aware[23] 서베이 + 본 연구 위치 | TXT |
| R1.4 | QUIC connection migration(RFC9000 §9) 제시 | §2.2 내 새 문단 | path probing·validation 설명 + "동시 multipath 센싱 없음"이 본 방식과의 차이 (mQUIC[22] 이미 인용됨과 연결) | TXT |
| R1.5 | Fig.3 구성요소 상세·구현 여부 | §3.1 (45–59) + Fig.3 캡션 | Sensing/Estimation/Decision 3모듈을 **구현 파일:함수에 1:1 매핑**(§구현명세 표) + 각 박스 실구현 명시 | TXT |
| R1.6 | min-max 정규화 수식 부재 | §3.3 (72–79) | 정규화 수식 3종(r̃,l̃,b̃) 번호 달아 명시 | EQ |
| R1.7 | PQI 정의 부재 | §3.3 | Cost `C_i=α·r̃+β·l̃+γ·(1−b̃)` + **`PQI_i=100·(1−C_i)`** 명시적 정의식 | EQ |
| R1.8 | path probing 전략 정의 | §3.2 (60–71) 또는 신규 | per-path RTT=ACK, loss=재전송/PATH_ACK, goodput=Δdelivered/Δt, RSSI=`iw dev link` 주기 샘플; 백업경로 probe 주기·조건 | TXT |
| R1.9 | 비디오 프레이밍: 전송계층이 프레임 경계를 어떻게 아나 | §3.4 (80–87) | 앱 프레이밍 명시: 9B 헤더 `[MPQ1][type(d/r)][BE len]`, 스트림별 길이 구분, depth/RGB 분리 SID | TXT |
| R1.10 | default·SP-QUIC+migration 베이스라인, SP-QUIC의 5G 불공정 | §4 전반 + 결과 | ① 베이스라인 `default`(minRTT), `spquic`(RFC9000 migration) 추가 ② **spquic이 WiFi 사망 시 핫스팟으로 migration** 하도록 수정(오늘 코드 완료) → 공정 | NUM+코드 |

## §2. Reviewer #2 대응

| ID | 코멘트 | 위치 | 조치 | 태그 |
|---|---|---|---|---|
| R2.1 | §2.1 "question"→"matter" | 문단 34 근처 | 단어 교체 | TXT |
| R2.2 | QUIC을 TCP "경쟁자/우월"로 프레이밍 말 것 | §2.2 (38) | 균형 있는 trade-off 서술로 리워딩 | TXT |
| R2.3 | MP-QUIC은 양 링크 동시 활성 → 엄밀히 handover 아님; soft-handover vs WiFi 무핸드오버 보완 | §2.2(39), §1 문제정의 | 용어 정의: 본 방식=**soft handover / make-before-break**. 문제=WiFi↔5G 전이 시 연속성(WiFi 자체 무핸드오버 아님)으로 일관화 | TXT |
| R2.4 | 왜 5G 패킷이 빠른가·왜 HoL 생기나 (QUIC은 본질적으로 HoL 회피) | §2.2(42) | 정정: per-stream 전달은 **경로 내** HoL 회피; 문제는 **경로 간** 스케줄링/재정렬(수신버퍼), 고전 TCP HoL 아님 | TXT |
| R2.5 | 3GPP N3IWF/ATSSS 고려 | §1 또는 §3.1 | N3IWF/ATSSS(네트워크계층 하이브리드) 소개 후 **전송계층 접근과 대비** 문단 | TXT |
| R2.6 | Fig.5 어떤 앱? total delay=파일전송시간? | §4.2.2 / §4 지표정의 | 워크로드=**비디오 프레임 스트림** 명시, "total transmission delay" 정의(프레임 시퀀스 완수 시간) | TXT |
| R2.7 | "cross traffic" 정의 | §4.2.3 결과 | 정의: iptables 확률 손실 램프(1→20%) + iperf3 배경 트래픽(방향/레이트/생성기) — 하네스 실측치와 일치 | TXT+NUM |
| R2.8 | "no traffic, no delay?"; 핸드오버 횟수 몇 번? 1번? | §4.2.3 | 시나리오 명확화 + **run당 핸드오버 이벤트 수 보고**(통계 파이프라인 산출) | NUM |
| R2.9 | 50/150 Mbps가 AMR에 현실적인가; 실제 요구 레이트는 훨씬 낮음 | §4.2.3 / testbed | 정당화: 다중카메라 depth+RGB 실측 레이트 명시(오늘 실측 ~20Mbps) + cross-traffic는 혼잡 스트레스용임을 구분 | TXT+NUM |
| R2.10 | Fig.8 handover 5.5s는 매우 김 | §4.3 / 결과 | 신 히스테리시스로 재측정한 핸드오버 지연 보고(구 값 원인=WiFi 절단 감지 vs 전송반응 분리 설명) | NUM |

## §3. Reviewer #3 대응

| ID | 코멘트 | 위치 | 조치 | 태그 |
|---|---|---|---|---|
| R3.1 | 무엇이 novel인가 | §1 기여(25–29), §3 | 기여 정밀화 (DEC-1) | TXT |
| R3.2 | "virtually eliminates service outages" 과장 | 초록, §1(29), 결론 | 측정 기반으로 완화: "reduces outage from X ms to <Y ms" | TXT+NUM |
| R3.3 | α,β,γ,T_deg,Δ_margin,T_stable,λ,W 미기재 | §3.3–3.4 | **파라미터 표** 신설(값+의미), `pqi_parameters.md`와 동기화 | TXT |
| R3.4 | PQI 이득 분리 안 됨; 표준 MP-QUIC(quic-go/xquic) 비교 | §4 결과 | 동일 스택 baseline(default/minRTT, RR) 비교 → 스케줄러만 변수 | NUM |
| R3.5 | 어떤 impl, 어떻게 수정, 어느 draft, PQI 어디 구현 | §3 또는 §4.1 | **구현 명세 문단**: picoquic 1.1.50.3, draft-20, PQI=`client_loop.c`(파일·함수), per-path 전송 | TXT (DEC-2) |
| R3.6 | 실제 이동 vs 에뮬레이션; AP배치·로봇속도·run수·5G종류·절단시간 | §4.1 testbed | 정직히 기술: nmcli 절단 에뮬 + 실주행 검증 병행; 파라미터 전부 명시 | TXT+NUM |
| R3.7 | §4.2.4 70ms "hesitation"=reactive failover이지 proactive 아님 | §4.4(153) | 용어 화해: RSSI-추세 **선제(proactive)** 경로 vs 사후 70ms **reactive** 폴백 구분; 선행시간(lead time) 실측 제시 | TXT+NUM |
| R3.8 | 반복수·평균·분산/CI·유의성 | §4 전반 | N=10, mean±95%CI, 유의성 검정 → 통계 파이프라인 | NUM |
| R3.9 | 왜 MP-QUIC 정상 처리량이 SP-QUIC보다 낮나(Table 2) | §4.2.1(116) | 원인 규명(스케줄러 오버헤드/재정렬) 후 설명 or 수정; 오늘 스모크상 baseline과 동등 관측 → 재측정으로 갱신 | NUM |
| R3.10 | Wi-Fi 표기 불일치, 저해상 figure, 수식 번호 | 전역 | "Wi-Fi"로 통일(정규식 치환), 전 수식 번호, figure 재생성 목록화 | TXT+EQ |

---

## §4. 실행 순서 (이번 세션 = TXT/EQ 먼저)

1. **[TXT] 전역 치환**: WiFi/Wifi/wifi/Wi-fi → "Wi-Fi"; "question"→"matter"(R2.1)
2. **[TXT] §2.2 재작성**: R1.1/1.2/1.4, R2.2/2.3/2.4 — draft 상태·스케줄러 impl-specific·migration·TCP 프레이밍·HoL 정정
3. **[TXT] 신규 소절 "MP-QUIC Schedulers"** (R1.3) + **N3IWF/ATSSS** 문단(R2.5)
4. **[EQ] §3.3 수식**: 정규화 3식 + Cost + PQI 정의 + 번호 (R1.6/1.7, R3.10)
5. **[TXT] §3.2 probing**(R1.8), **§3.4 framing**(R1.9), **파라미터 표**(R3.3)
6. **[TXT] 구현 명세 문단**(R3.5, DEC-2) + **Fig.3 모듈→코드 매핑**(R1.5)
7. **[TXT] §1 기여 정밀화**(R3.1) + **주장 완화**(R3.2) — 수치자리 `【NUM】`
8. **[TXT] §4.1 testbed 재작성**(R3.6, R2.6/2.9): 워크로드·절단방식·파라미터·레이트
9. **[TXT] 결과 서술 골격**: baseline 비교·통계·proactive/reactive(R1.10,R3.4,R3.7,R3.8) 문장 틀 + 표/그림 자리 `【NUM】`

## §5. 매트릭스 완료 후 채울 [NUM] 목록 (플레이스홀더 → 실측)
- Table 2 전체(정상 처리량 4모드, 스위칭 지연, 총지연) — R3.9 포함
- Fig.5 총전송지연 vs 핸드오버 타이밍 (4모드)
- Fig.6 핸드오버 지연 분포 (box, N=10, CI)
- Fig.7 cross-traffic 0/50/150Mbps 견고성
- Fig.8 disconnect–recovery 처리량 타임라인 (outage 구간 실측)
- Fig.9 micro: 선제 lead time(R3.7) + 복구 reactivation
- run당 핸드오버 횟수(R2.8), proactive 선행시간(R3.7), outage 지속(R2.10/R3.2)

## §6. Figure 재생성 목록 (R3.10 저해상) — 별도 작업
Fig.1(AP handover), Fig.2(network model), Fig.3(architecture), Fig.4(scenarios): 벡터 재작도.
Fig.5–9: 매트릭스 데이터로 신규 플롯(dataviz 표준).
