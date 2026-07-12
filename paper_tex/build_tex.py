#!/usr/bin/env python3
# Convert pandoc bootstrap (paper_body.tex) into a clean elsarticle paper.tex:
# strip quote/enumerate cruft, real LaTeX equations, thebibliography + new refs,
# integrate the cited related-work paragraphs, fix figures, de-unicode for pdflatex.
import re, io

src = open('paper_tex/paper_body.tex', encoding='utf-8').read()

# ── 1. drop quote wrappers ──
src = re.sub(r'\\begin\{quote\}\n?', '', src)
src = re.sub(r'\\end\{quote\}\n?', '', src)

# ── 1b. extract the references enumerate BEFORE we strip enumerates; replace
#    the whole "References + list" block with a token restored at the end. ──
existing_items = []
mm = re.search(r'References\s*\n+\\begin\{enumerate\}(.*?)\\end\{enumerate\}', src, re.S)
if mm:
    for it in re.findall(r'\\item\s*\n?(.*?)(?=\\item|\Z)', mm.group(1), re.S):
        t = it.strip()
        if t: existing_items.append(re.sub(r'\s+', ' ', t))
    src = src[:mm.start()] + '\n%%REFS%%\n' + src[mm.end():]

# ── 1c. swap the two skeleton related-work paragraphs for the cited versions
#    (citations verified via deep-research; numbers match thebibliography order). ──
SCHED_CITED = ("A substantial body of work has studied packet scheduling for multipath transport, "
 "and it is useful to position our scheduler against it. The default schedulers---lowest-RTT "
 "(minRTT) and round-robin---maximize throughput on homogeneous paths but perform poorly on "
 "heterogeneous Wi-Fi/cellular paths, where sending on a slow subflow induces out-of-order "
 "delivery and receiver-side head-of-line (HoL) blocking [30], [31]. Heterogeneity-aware "
 "heuristics address this: BLEST proactively estimates whether using a slow subflow would cause "
 "HoL blocking and skips it, reducing spurious retransmissions [31], while ECF (Earliest "
 "Completion First) selects paths by estimated completion time using RTT, congestion window, and "
 "buffer occupancy rather than RTT alone [30]. A second line of work applies online learning: "
 "Peekaboo uses reinforcement learning to adapt to dynamic, heterogeneous paths [32], FALCON adds "
 "meta-learning for fast adaptation to time-varying links [33], and DQN- and multi-agent-DRL "
 "schedulers optimize video-streaming QoE [34], [35]. Application- and mobility-aware designs are "
 "closest to our setting: the stream-aware MPQUIC scheduler of Xing et al. maps streams to paths "
 "by traffic semantics [23], and MAMS forecasts fast-changing wireless links to mitigate "
 "out-of-order delivery under mobility [13]. Field studies confirm that learning-based schedulers "
 "can outperform heuristics under real urban mobility, though the advantage is condition-dependent "
 "[36]. Across this body of work, however, the objective is aggregate throughput, completion time, "
 "or video QoE, and mobility is handled at most implicitly through transport-observable metrics "
 "(RTT, loss, delivery rate); none couples a radio-layer signal (RSSI) with proactive, "
 "pre-emptive handover at the transport scheduler. Our scheduler targets exactly that gap: it "
 "augments a normalized transport-quality index with a Wi-Fi RSSI trend so that it can vacate a "
 "degrading Wi-Fi path before the transport metrics---and the resulting HoL blocking---appear.")
N3IWF_CITED = ("At the network layer, 3GPP has made the 5G System natively multi-access. Untrusted "
 "non-3GPP access such as Wi-Fi attaches to the 5G core through the Non-3GPP Interworking Function "
 "(N3IWF), a core-anchored gateway that terminates the N2/N3 interfaces and an IPsec tunnel from "
 "the device, as specified in 3GPP TS 23.501 [37]. Building on this, the Access Traffic Steering, "
 "Switching and Splitting (ATSSS) framework---introduced in Release 16 and defined jointly by "
 "TS 23.501, TS 23.502, and the Stage-3 specification TS 24.193---lets a Multi-Access PDU session "
 "steer, switch, and split user traffic across the 5G-NR and Wi-Fi accesses, using an MPTCP proxy "
 "in the User Plane Function and, since Release 18, an MPQUIC-based mode [37], [38], [39]. However, "
 "ATSSS steering is bound to and controlled by the 5G core: the Policy Control Function derives the "
 "policy and the Session Management Function pushes rules to the UPF and the device, so "
 "distribution follows operator policy rather than application intent, and the Release-16 split "
 "uses a static, pre-provisioned weight that cannot track real-time link status [40], [41]. "
 "Enabling such multi-access sessions thus requires tight integration with the operator's 5G core "
 "[40]. In contrast, our transport-layer approach based on MP-QUIC is driven end-to-end by the "
 "application endpoints and provides session continuity across heterogeneous accesses without "
 "dependence on 5G-core integration or operator control---precisely what ATSSS and N3IWF, by "
 "design, do not themselves offer.")
src = re.sub(r"A substantial body of work has studied packet scheduling for multipath transport\..*?before the transport metrics reflect the degradation\.",
             lambda m: SCHED_CITED, src, flags=re.S)
src = re.sub(r"At the network layer, 3GPP defines the Non-3GPP Interworking Function.*?under the direct control of the AMR endpoint\.",
             lambda m: N3IWF_CITED, src, flags=re.S)

# ── 2. headings: pandoc turned ALL headings into (nested) enumerate scaffolding
#    (contributions/scenarios are plain "•" paragraphs, not enumerates). Strip
#    every enumerate scaffold line, then map the bare title lines to sections. ──
SECTIONS = ['Introduction','Related Works',
            'Proposed MP-QUIC Transmission for handover of AMRs',
            'Performance Evaluation by Experimentation','Conclusions and Future Works','References']
SUBSECTIONS = ['Autonomous Mobile Robot','QUIC and MP-QUIC','MP-QUIC Path Schedulers',
               'System Architecture and Overview','Network Sensing and Metric Collection',
               'Path Quality Estimation','Path Selection and Failover Scheduling','Implementation',
               'Testbed Configuration','Results and Discussion','Summary of Performance Comparison',
               'Overall Throughput','Handover latency','End-to-end and micro-level handover behavior']
# 2a. pull subsection titles out of \emph{} first (so bare-title map catches them)
for t in SUBSECTIONS:
    src = re.sub(r'\\emph\{'+re.escape(t)+r'\}', t, src)
# 2b. strip all enumerate scaffolding lines
src = re.sub(r'^\s*\\(begin|end)\{enumerate\}\s*$', '', src, flags=re.M)
src = re.sub(r'^\s*\\def\\labelenum[^\n]*$', '', src, flags=re.M)
src = re.sub(r'^\s*\\setcounter\{enum[^\n]*$', '', src, flags=re.M)
src = re.sub(r'^\s*\\tightlist\s*$', '', src, flags=re.M)
src = re.sub(r'^\s*\\item\s*$', '', src, flags=re.M)
# 2c. bare title line → \section / \subsection (longest-first to avoid partial hits)
for t in sorted(SECTIONS, key=len, reverse=True):
    src = re.sub(r'^\s*'+re.escape(t)+r'\s*$', r'\\section{'+t+'}', src, flags=re.M)
for t in sorted(SUBSECTIONS, key=len, reverse=True):
    src = re.sub(r'^\s*'+re.escape(t)+r'\s*$', r'\\subsection{'+t+'}', src, flags=re.M)

# ── 4. citations {[}n{]} → [n] ──
src = src.replace('{[}','[').replace('{]}',']')

# ── 5. equations: replace the text-equation lines with real math ──
EQS = {
 1: r'\tilde{r}_i = \frac{r_i - r_{\min}}{r_{\max}-r_{\min}},\quad \tilde{l}_i = \frac{l_i - l_{\min}}{l_{\max}-l_{\min}},\quad \tilde{b}_i = \frac{b_i - b_{\min}}{b_{\max}-b_{\min}}',
 2: r'C_i^{\mathrm{tr}} = \alpha\,\tilde{r}_i + \beta\,\tilde{l}_i + \gamma\,(1-\tilde{b}_i),\qquad \alpha+\beta+\gamma=1',
 3: r'\rho_i = \operatorname{clamp}\!\left(\frac{S_{\mathrm{good}}-s_i}{S_{\mathrm{good}}-S_{\mathrm{unusable}}},\,0,\,1\right)',
 4: r'C_i = \frac{\alpha\,\tilde{r}_i + \beta\,\tilde{l}_i + \gamma\,(1-\tilde{b}_i) + \omega\,\rho_i}{1+\omega}',
 5: r'\mathrm{PQI}_i = 1000\,C_i',
 6: r'\mathrm{PQI}_i(t) = \lambda\,\mathrm{PQI}_i^{\mathrm{raw}}(t) + (1-\lambda)\,\mathrm{PQI}_i(t-1)',
 7: r'\text{switch } a\!\to\!c \iff \mathrm{PQI}_a \ge T_{\deg}\ \wedge\ \mathrm{PQI}_a-\mathrm{PQI}_c \ge \Delta\ \ (\text{sustained} \ge T_{\mathrm{stable}})',
 8: r'\text{switch } a\!\to\!c \iff s_a \le S_{\mathrm{bad}}',
}
def eq_line(m):
    n=int(m.group('n'))
    if n in EQS:
        return f'\\begin{{equation}}\\label{{eq:{n}}}\n{EQS[n]}\n\\end{{equation}}'
    return m.group(0)
# match a whole line ending in (N) that looks like one of our equation lines
src = re.sub(r'^\s*(?:switch|r̃|C\\?_i|ρ|PQI|.*=).*?\((?P<n>[1-8])\)\s*$', eq_line, src, flags=re.M)

# ── 6. figures: media/imageN.png → figures/imageN.png; wrap as figure floats ──
src = src.replace('media/image','figures/image')

# ── 7. de-unicode remaining text (pdflatex-safe) ──
UNI = {'≥':r'$\ge$','≤':r'$\le$','−':'-','×':r'$\times$','∼':r'$\sim$','∈':r'$\in$',
 '∧':r'$\wedge$','→':r'$\rightarrow$','α':r'$\alpha$','β':r'$\beta$','γ':r'$\gamma$',
 'λ':r'$\lambda$','ω':r'$\omega$','Δ':r'$\Delta$','ρ':r'$\rho$','δ':r'$\delta$',
 'μ':r'$\mu$','·':r'$\cdot$','∆':r'$\Delta$','⁠':'', ' ':' ', '​':'',
 'Ω':r'$\Omega$','‑':'-','–':'--','—':'---','…':r'\ldots','’':"'",'‘':"'",'“':'``','”':"''",
 'ř':r'\v{r}','Ö':r'\"O','ö':r'\"o','á':r"\'a",'å':r'\aa{}','é':r"\'e",'ü':r'\"u',
 'Ž':r'\v{Z}','ľ':r"\'l",'ž':r'\v{z}','Ａ':'A'}
# strip combining tilde sequences that survive outside equations
src = src.replace('r̃','r').replace('l̃','l').replace('b̃','b')
for u,l in UNI.items(): src = src.replace(u,l)
# editorial Korean note inside the remaining CONFIRM marker → English
src = src.replace('AP 배치/로봇 속도 - 실주행 검증 시 값 기입 (R3.6)',
                  'AP layout and robot speed to be supplied from field validation (R3.6)')
# safety: any remaining Hangul (editorial notes) is not for the typeset PDF
src = re.sub(r'[가-힣]+', '[TBD]', src)
# 【NUM】/【CONFIRM】 markers → visible placeholder boxes
src = src.replace('【','\\textbf{[').replace('】',']}')

# ── 8. references: build thebibliography and restore at %%REFS%% token ──
NEW_REFS = [
 r'Y. Lim, E. Nahum, D. Towsley, and R. Gibbens, ``ECF: An MPTCP Path Scheduler to Manage Heterogeneous Paths,'''+ "'" + r"' in Proc. ACM CoNEXT, 2017. DOI: 10.1145/3143361.3143376.",
 r"S. Ferlin, \"O. Alay, O. Mehani, and R. Boreli, ``BLEST: Blocking Estimation-based MPTCP Scheduler for Heterogeneous Networks,'' in Proc. IFIP Networking, 2016.",
 r"H. Wu, \"O. Alay, A. Brunstr\"om, S. Ferlin, and G. Caso, ``Peekaboo: Learning-Based Multipath Scheduling for Dynamic Heterogeneous Environments,'' IEEE J. Sel. Areas Commun., vol. 38, no. 10, pp. 2295--2310, 2020. DOI: 10.1109/JSAC.2020.3000365.",
 r"H. Wu, G. Caso, S. Ferlin, \"O. Alay, and A. Brunstr\"om, ``FALCON: Fast and Accurate Multipath Scheduling using Offline and Online Learning,'' arXiv:2201.08969, 2022.",
 r"M. Lee and J. Yoo, ``Reinforcement Learning Based Multipath QUIC Scheduler for Multimedia Streaming,'' Sensors, vol. 22, no. 17, art. 6333, 2022. DOI: 10.3390/s22176333.",
 r"X. Han et al., ``MARS: A DRL-based Multi-Agent Multipath Scheduler for MPQUIC Video Streaming,'' ACM Trans. Multimedia Comput. Commun. Appl., 2024. DOI: 10.1145/3649139.",
 r"A. Diakhate et al., ``Experimental Evaluation of Multiple Multipath Schedulers over Various Urban Mobile Environments,'' in Proc. SoICT, 2022. DOI: 10.1145/3568562.3568655.",
 r'3GPP, ``System architecture for the 5G System (5GS); Stage 2,'''+ "'" + r"' 3GPP TS 23.501, Release 16.",
 r'3GPP, ``Procedures for the 5G System (5GS); Stage 2,'''+ "'" + r"' 3GPP TS 23.502, Release 16.",
 r'3GPP, ``5G System; Access Traffic Steering, Switching and Splitting (ATSSS); Stage 3,'''+ "'" + r"' 3GPP TS 24.193, V16.0.0, Release 16.",
 r"R. Schmidt et al., ``5G-MANTRA: A Standards-Compliant MPTCP Proxy for Enabling ATSSS,'' in Proc. ACM 5G-MeMU Workshop, 2023. DOI: 10.1145/3609382.3610511.",
 r"``Enhanced Access Traffic Steering, Switching and Splitting (ATSSS) in 5G,'' arXiv:2302.05439, 2023.",
]
allrefs = existing_items + NEW_REFS
bib = '\\section*{References}\n\\begin{thebibliography}{99}\n' + \
      '\n'.join(f'\\bibitem{{r{i+1}}} {r}' for i,r in enumerate(allrefs)) + \
      '\n\\end{thebibliography}\n'
src = src.replace('%%REFS%%', bib)

# ── 9. wrap figures: bare \includegraphics + following "Figure N:" caption → float ──
def fig_float(m):
    inc, cap = m.group(1), m.group(2).strip()
    return ('\\begin{figure}[!t]\n\\centering\n\\includegraphics[width=0.8\\linewidth]{'
            + inc + '}\n\\caption{' + cap + '}\n\\end{figure}\n')
src = re.sub(r'\\includegraphics\[[^\]]*\]\{([^}]+)\}\s*\n+\s*(Figure [^\n]+)', fig_float, src)
# table captions "Table N: ..." keep as centered bold line above longtable already present

# ── assemble full document ──
PRE = r'''\documentclass[11pt]{article}
\usepackage[a4paper,margin=1in]{article}
'''
# elsarticle preferred; fall back handled at compile
PREAMBLE = r'''\documentclass[preprint,11pt]{elsarticle}
\usepackage{amsmath,amssymb}
\usepackage{graphicx}
\usepackage{booktabs}
\usepackage{array}
\usepackage{calc}
\usepackage{longtable}
\usepackage[hidelinks]{hyperref}
% pandoc longtable/list helper macros
\providecommand{\real}[1]{#1}
\providecommand{\tightlist}{\setlength{\itemsep}{0pt}\setlength{\parskip}{0pt}}
\journal{Computer Communications}
\begin{document}
\begin{frontmatter}
\title{MP-QUIC for Seamless Handover of Autonomous Mobile Robots in Heterogeneous Networks}
\author[a]{Dohyeon Lim}
\author[b]{Seok-Joo Koh\corref{cor}}
\cortext[cor]{Corresponding author}
\affiliation[a]{organization={Department of Data Convergence Computing, Kyungpook National University},country={Republic of Korea}}
\affiliation[b]{organization={School of Computer Science and Engineering, Kyungpook National University},country={Republic of Korea}}
'''

# extract abstract + keywords from src, drop the duplicated title/author lines pandoc made
# find abstract text (first big para after the author block) and keywords line
abs = re.search(r'Abstract\s*\n+(.*?)\n+Keywords:\s*([^\n]+)', src, re.S)
abstract = re.sub(r'\s+',' ',abs.group(1)).strip() if abs else 'ABSTRACT'
keywords = abs.group(2).strip() if abs else ''
FRONT = ('\\begin{abstract}\n'+abstract+'\n\\end{abstract}\n'
         '\\begin{keyword}\n'+keywords.replace('Keywords:','').strip()+'\n\\end{keyword}\n'
         '\\end{frontmatter}\n')

# body = everything from "Introduction" section onward
bstart = src.find('\\section{Introduction}')
body = src[bstart:] if bstart>=0 else src
# remove any leftover author/title/abstract lines before body already handled

doc = PREAMBLE + FRONT + body + '\n\\end{document}\n'
open('paper_tex/paper.tex','w',encoding='utf-8').write(doc)
print('wrote paper_tex/paper.tex chars', len(doc))
print('existing refs parsed:', len(existing_items), '| total refs:', len(allrefs))
