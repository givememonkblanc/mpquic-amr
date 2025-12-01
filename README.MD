좋아. 지금 너가 깃허브에 올리려고 하는 **MP-QUIC 프로젝트**를 위한 README.md는 *아카데믹 + 엔지니어링 + 실험 프로젝트*의 성격을 동시에 담아야 해.
코드는 C 기반(Picoquic)이고, 구조적으로 client/server + PQI 기반 path algorithm + frame assembler + pcaps까지 있는 형태라, **연구용 + 실험용 QUIC Mobility Framework**라는 포지션이 좋다.

아래는 **그대로 복붙해서 깃허브에 올려도 되는 수준의 High-quality README.md**야.
(너의 박사 프로젝트 설명, PQI, Failover, 라즈베리파이 실험까지 다 녹여 넣음)

---

# 🚀 Adaptive MP-QUIC Mobility Framework

**RTT/Loss/Bandwidth-based Path Quality Index(PQI) for Seamless Handover in Mobile Robots (AMR)**
*A research-driven QUIC mobility framework built on Picoquic*

---

## 📌 Overview

This project is an experimental **Adaptive MP-QUIC Transport Framework** designed for mobility-critical environments such as **Autonomous Mobile Robots (AMRs)**.
It extends the Picoquic QUIC stack with:

* **RTT / Loss / Bandwidth–based Path Quality Index (PQI)**
* **Adaptive Path Selection & Fast Failover**
* **Real-time frame delivery & QoE tracking**
* **Client–Server modules for multi-path video / telemetry streaming**
* **PCAP-based path performance analysis**

The system was validated on **Raspberry Pi mobility testbeds** under Wi-Fi degradation, outage, and LTE fallback scenarios.

---

## ✨ Key Features

### 🔗 Adaptive MP-QUIC Transport

* PQI(Path Quality Index) = *f(RTT, loss rate, available bandwidth)*
* Immediate failover when PQI degrades (Wi-Fi → LTE, etc.)
* Cost-based path decisions during stable intervals

### 🚀 Sub-1s Failover (Validated)

* AMR 이동 중 Wi-Fi 단절 환경에서
  **LTE 경로를 통해 12.5 Mbps 지속 전송**
* 단절 후 **1초 이내 failover 완료**
* 스트림 drop 없이 연속 프레임 전송 성공

### 🧪 Full Testbed Architecture

* Raspberry Pi sender (client)
* Edge server (receiver)
* Multi-interface mobility (Wi-Fi / LTE Hotspot)
* PCAP logging + RTT/loss computation

---

## 📁 Project Structure

```
mpquic/
│
├── build/                          # Build artifacts (picoquic static libs, demos)
│   ├── third_party/picoquic        # Bundled picoquic build output
│   ├── cli / picoquicdemo
│   ├── server_recv / client_uploader
│
├── certs/                          # TLS certificates
│   ├── cert.pem
│   └── key.pem
│
├── client/
│   ├── camera.cpp / camera.h       # Camera frame capture module
│   ├── client_uploader.c           # QUIC client uploader
│   ├── path_algo.c / path_algo.h   # Adaptive PQI-based path algorithm
│   └── CMakeLists.txt
│
├── server/
│   ├── server_recv.c               # QUIC server stream receiver
│   ├── frame_assembler.c/.h        # Frame reconstruction logic
│   └── app_ctx.h
│
├── configs/                        # Runtime configs
├── scripts/                        # Utility scripts (cert generation, tests)
└── CMakeLists.txt                  # Project build config
```

---

## 🔧 Build & Run

### 1. Clone & Initialize

```bash
git clone https://github.com/yourname/mpquic-mobility.git
cd mpquic-mobility
git submodule update --init --recursive
```

### 2. Build (CMake)

```bash
mkdir build && cd build
cmake ..
make -j4
```

### 3. Run Server

```bash
./server_recv -p 4433 \
  --cert ../certs/cert.pem \
  --key ../certs/key.pem
```

### 4. Run Client (Wi-Fi + LTE Interfaces)

```bash
./client_uploader \
   <server_ip> \
   <client_ip> \ 
   <client_mp_ip> \ 
```

---

## 📡 Path Quality Index (PQI) Formula (Simplified)

```text
PQI = α * RTT_normalized 
    + β * LossRate 
    + γ * (1 - BandwidthScore)
```

* **Low PQI → degrade → trigger immediate failover**
* **High PQI → balanced cost-based scheduling**

You can modify weight factors in:

```
client/path_algo.c
```

---

## 📉 Example Experiment Results

| Scenario                                 | Result                                |
| ---------------------------------------- | ------------------------------------- |
| Wi-Fi degradation (packet loss injected) | PQI drops → LTE takeover within 0.4 s |
| Wi-Fi hard outage                        | LTE maintains ~12.5 Mbps throughput   |
| Wi-Fi recovery                           | PQI surpasses LTE → path restored     |
| High-motion AMR mobility                 | No frame loss, stable continuity      |

---

## 📊 PCAP & Logging

The system logs:

* Per-path RTT
* Loss ratio
* Reordering
* Send/recv timestamps
* Path verification events
* Switch-over events (failover)

To analyze:

```bash
tshark -r mpquic_trace.pcap
```

---

## 📌 Research Background

This framework is part of my ongoing **doctoral research** on AI-driven communication systems at Kyungpook National University.

Published / Submitted Works:

* **KCI Journal (2025):** Deep-learning maritime fog detection
* **UCWIT (2025 Submission):** Adaptive MP-QUIC mobility model for AMR

---

## ❤️ Contribution

Pull requests are welcome—especially for:

* Better congestion control tuning
* PQI model extensions
* Client camera streaming improvements
* Mobility emulation scripts

---

## 📜 License

MIT License (or you choose)

---

## 🧑‍🔬 Author

**임도현 (Do Hyeon Lim)**
AI Engineer & PhD Researcher
AI-driven Communication Systems / MP-QUIC / Autonomous Robots
📧 [ldh97710@gmail.com](mailto:ldh97710@gmail.com)
