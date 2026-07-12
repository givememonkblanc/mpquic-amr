# Related Work 문헌조사 — TOPIC A: MP-QUIC/Multipath Schedulers (R1.3)

deep-research: 10 verified findings (adversarial verify 통과).

### [1] (high)
The default minRTT scheduler (used in both MPTCP and MPQUIC) selects the lowest-RTT subflow that has congestion-window (CWND) space; while this maximizes throughput on homogeneous paths, it underutilizes the fast path and suffers head-of-line (HoL) blocking on heterogeneous paths, reactively penalizing/retransmitting on slow subflows and degrading latency-sensitive traffic such as video streaming.
**IEEE:** Y. Lim, E. Nahum, D. Towsley, and R. Gibbens, 'ECF: An MPTCP Path Scheduler to Manage Heterogeneous Paths,' in Proc. ACM CoNEXT, 2017, doi: 10.1145/3143361.3143376.
**Sources:** https://dl.acm.org/doi/10.1145/3143361.3143376 ; https://arxiv.org/html/2511.14550v1 ; https://arxiv.org/pdf/2201.08969

### [2] (high)
Round-robin multipath scheduling offers load-balancing and equal subflow use on homogeneous paths but is detrimental on highly heterogeneous paths (out-of-order arrival, HoL blocking, receive-window limiting, retransmissions), which matters when positioning classic schedulers in a heterogeneous Wi-Fi/5G setting.
**Sources:** https://arxiv.org/html/2511.14550v1

### [3] (high)
BLEST (Blocking Estimation) is a PROACTIVE MPTCP scheduler that estimates whether scheduling on a currently available slow subflow would cause HoL blocking when the fast subflow becomes free, and skips it to wait for the better path — targeting minimized HoL blocking and capacity aggregation in heterogeneous networks; it reports ~12% higher application goodput for bulk traffic and ~80% fewer spurious retransmissions vs. default MPTCP and other schedulers.
**IEEE:** S. Ferlin, O. Alay, O. Mehani, and R. Boreli, 'BLEST: Blocking Estimation-based MPTCP Scheduler for Heterogeneous Networks,' in Proc. IFIP Networking, 2016. (DOI unverified; IEEE Xplore document 7497206.)
**Sources:** https://dl.ifip.org/db/conf/networking/networking2016/1570234725.pdf ; https://arxiv.org/html/2511.14550v1

### [4] (high)
ECF (Earliest Completion First) is an MPTCP path scheduler by Lim, Nahum, Towsley, and Gibbens (ACM CoNEXT 2017, DOI 10.1145/3143361.3143376) that decides whether to wait for the fast path or use a slower one based on estimated completion time, using RTT, path bandwidth (congestion window), and send-buffer occupancy rather than RTT alone; it maximizes fast-path utilization and minimizes download/completion time under static WiFi+cellular heterogeneity, but does NOT address mobility, RSSI, or handover continuity.
**IEEE:** Y. Lim, E. Nahum, D. Towsley, and R. Gibbens, 'ECF: An MPTCP Path Scheduler to Manage Heterogeneous Paths,' in Proc. ACM CoNEXT, 2017, doi: 10.1145/3143361.3143376.
**Sources:** https://dl.acm.org/doi/10.1145/3143361.3143376 ; https://www.researchgate.net/publication/319946409_ECF_An_MPTCP_Path_Scheduler_to_Manage_Heterogeneous_Paths ; https://arxiv.org/html/2511.14550v1

### [5] (high)
Peekaboo (Wu et al., IEEE JSAC 2020) is a learning-based online reinforcement-learning multipath scheduler implemented in MPQUIC that specifically targets the failure of state-of-the-art schedulers on heterogeneous paths with DYNAMIC characteristics (packet loss, delay fluctuation — i.e., path degradation), learning scheduling decisions over time based on current path characteristics and dynamicity levels.
**IEEE:** H. Wu, O. Alay, A. Brunstrom, S. Ferlin, and G. Caso, 'Peekaboo: Learning-Based Multipath Scheduling for Dynamic Heterogeneous Environments,' IEEE J. Sel. Areas Commun., vol. 38, no. 10, pp. 2295-2310, 2020. (Volume/issue/pages unverified; DOI 10.1109/JSAC.2020.3000365 unverified.)
**Sources:** https://ieeexplore.ieee.org/document/9110610/

### [6] (high)
FALCON (Wu et al., arXiv 2201.08969) is a learning-based MPQUIC scheduler using META-LEARNING — offline learning builds coarse-grained meta-models and online learning bootstraps a fine-grained model — to adapt fast and accurately to time-varying network conditions such as mmWave 5G and WLAN paths.
**IEEE:** H. Wu, O. Alay, A. Brunstrom, G. Caso, and S. Ferlin, 'FALCON: Fast and Accurate Multipath Scheduling using Offline and Online Learning,' arXiv:2201.08969, 2022.
**Sources:** https://arxiv.org/pdf/2201.08969

### [7] (high)
Lee & Yoo (MDPI Sensors 2022, 22(17):6333, DOI 10.3390/s22176333) propose a deep-reinforcement-learning MPQUIC scheduler built on a Deep Q-Network (DQN) that optimizes for DASH video streaming (reward tied to per-chunk download time and size) rather than raw throughput/completion time; it does NOT address mobility, handover, or RSSI-driven switching — evaluation is limited to static Mininet configurations and packet-loss scenarios, leaving handover continuity as a gap.
**IEEE:** M. Lee and J. Yoo, 'Reinforcement Learning Based Multipath QUIC Scheduler for Multimedia Streaming,' Sensors, vol. 22, no. 17, art. 6333, 2022, doi: 10.3390/s22176333.
**Sources:** https://www.mdpi.com/1424-8220/22/17/6333

### [8] (high)
MARS (Han et al., IEEE/ACM IWQoS 2023; journal version ACM TOMM DOI 10.1145/3649139) is a multi-agent deep-reinforcement-learning (MADRL) MPQUIC scheduler that learns a separate neural network per path to generate the scheduling policy, and optimizes a multi-objective reward combining out-of-order (OFO) queue size and QoS metrics rather than raw aggregate throughput alone.
**IEEE:** X. Han et al., 'Multi-agent DRL-based Multipath Scheduling for Video Streaming with QUIC,' ACM Trans. Multimedia Comput. Commun. Appl., 2024, doi: 10.1145/3649139; conf. version 'MARS: An Adaptive Multi-Agent DRL-based Scheduler for Multipath QUIC in Dynamic Networks,' IEEE/ACM IWQoS, 2023 (doc 10188744).
**Sources:** https://dl.acm.org/doi/10.1145/3649139

### [9] (high)
MAMS (Yang, Cai, Shu, Pan, Sepahi, IEEE/ACM Transactions on Networking, vol. 32, no. 4, pp. 3237-3252, 2024) is the mobility-aware MPQUIC scheduler most aligned with continuity: it introduces link/transport-layer interaction (MMQUIC), forecasts uplink/downlink path conditions under fast-changing wireless links, and pre-allocates packets to mitigate out-of-order (OFO) delivery that harms QoE in mobile environments — a continuity/QoE objective rather than solely maximizing aggregate throughput.
**IEEE:** W. Yang, L. Cai, S. Shu, J. Pan, and A. Sepahi, 'MAMS: Mobility-Aware Multipath Scheduler for MPQUIC,' IEEE/ACM Trans. Netw., vol. 32, no. 4, pp. 3237-3252, 2024, doi: 10.1109/TNET.2024.3384817 (DOI unverified).
**Sources:** https://ieeexplore.ieee.org/document/10486871/

### [10] (medium)
An independent SoICT 2022 experimental study (Diakhate et al., DOI 10.1145/3568562.3568655) evaluated four state-of-the-art MPQUIC schedulers (minRTT, BLEST, ECF, and learning-based Peekaboo) in real-world urban mobility (train and car) around Paris using a purpose-built modular scheduler assessment framework, and found the learning-based scheduler outperformed the heuristic schedulers in those urban-mobility experiments (minRTT worst most of the time).
**IEEE:** A. Diakhate et al., 'Experimental Evaluation of Multiple Multipath Schedulers over Various Urban Mobile Environments,' in Proc. SoICT, 2022, doi: 10.1145/3568562.3568655.
**Sources:** https://dl.acm.org/doi/fullHtml/10.1145/3568562.3568655

## Synthesis (Related Work 초안용)
This synthesis covers TOPIC A only (MP-QUIC/multipath schedulers); the 23 verified claims contain no evidence for TOPIC B (3GPP N3IWF/ATSSS), which must be sourced separately. For Topic A, the literature splits cleanly into (i) completion-time/throughput-oriented schedulers — minRTT (default, HoL-blocking-prone on heterogeneous paths), round-robin (detrimental on heterogeneous paths), BLEST (proactive HoL-blocking estimation), and ECF (earliest-completion-first using RTT+CWND+send-buffer) — and (ii) learning-based schedulers — Peekaboo (online MAB RL, handles dynamic path degradation), FALCON (meta-learning for time-varying mmWave-5G/WLAN), and DQN/MADRL variants (Lee & Yoo's DASH-QoE DQN; MARS's multi-agent OFO+QoS reward). Critically, only MAMS (Yang et al., IEEE/ACM ToN 2024) is explicitly mobility/continuity-aware, forecasting fast-changing wireless links to mitigate out-of-order delivery — yet even it does not use RSSI signals or model network handover events directly. The state of the art therefore optimizes aggregate throughput, completion time, or video QoE/OFO, with mobility treated at most implicitly; none couples radio-signal (RSSI) awareness with proactive handover at the transport scheduler, which is precisely the gap an RSSI-augmented, handover-aware MP-QUIC scheduler fills. An independent SoICT 2022 field study around Paris confirms learning-based schedulers beat heuristics under urban mobility, though a 2025 study shows that advantage is condition-specific.

## Caveats / DOI 미검증
TOPIC B IS ENTIRELY MISSING from the verified claim set: there are zero confirmed claims about N3IWF, ATSSS, or 3GPP specs (TS 23.501/23.502/24.193). The paper's Topic B Related Work subsection cannot be written from this evidence and requires a separate literature pass (recommend citing 3GPP TS 23.501 Rel-16/17 for 5GS architecture incl. non-3GPP access, TS 23.502 for procedures, and TS 24.193 for the MPTCP/ATSSS 5GC user-plane, plus an ATSSS survey/measurement paper such as work in IEEE Access or Computer Networks). Several DOIs are UNVERIFIED and should be flagged in the manuscript: BLEST (IFIP Networking 2016 — no CrossRef DOI; cite IEEE Xplore doc 7497206), Peekaboo (JSAC 2020 vol/issue/pages and DOI 10.1109/JSAC.2020.3000365 not independently confirmed here), MAMS (DOI 10.1109/TNET.2024.3384817 inferred, not verified — vol/issue/pages/authors ARE confirmed). Verified DOIs: ECF (10.1145/3143361.3143376), Lee & Yoo Sensors (10.3390/s22176333), MARS (10.1145/3649139), Diakhate SoICT (10.1145/3568562.3568655). Time-sensitivity: the Peekaboo-beats-heuristics result is condition-specific and partially contradicted under highly dynamic 2D/3D mobility by a 2025 Computer Networks study — state it as an in-experiment finding, not a universal claim. FALCON is an arXiv preprint (2201.08969); check for a peer-reviewed venue before final submission. Two claims were refuted in verification (specific M-Peekaboo/Reles/LinUCB details, and a '20% gain' figure) and were excluded.