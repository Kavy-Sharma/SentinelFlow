# SentinelFlow: 8–10 Minute Video Demonstration Script

**Target Duration:** 9 minutes 30 seconds (9:30)  
**Project:** SentinelFlow — Explainable Hybrid Network Intrusion Detection System (NIDS)  
**Presenter:** Cybersecurity Engineering Candidate  
**Environment:** Python 3.11 User-Space (Terminal, Browser, VS Code)  

---

## Pre-Recording Verification Checklist

Before starting the recording, verify that all prerequisites are satisfied:

- [ ] **Python 3.11 Virtual Environment**: Activated (`.venv`) in PowerShell / Bash.
- [ ] **Dependencies & Package**: Installed (`pip install -r requirements.txt && pip install -e .`).
- [ ] **Synthetic Datasets**: Generated in `data/pcaps` and `data/pcaps_holdout`:
  ```bash
  python -m sentinelflow.generator --scenario all --seed 42 --out data/pcaps --generate-holdout
  ```
- [ ] **Trained Model Artifact**: Present at `models/isolation_forest.joblib`:
  ```bash
  python -m sentinelflow.cli train --benign data/pcaps/s1_benign.pcap --out models/isolation_forest.joblib
  ```
- [ ] **Sample Detection Directory**: Cleaned and regenerated:
  ```bash
  python -m sentinelflow.cli detect data/pcaps/s2_port_scan.pcap --mode hybrid --out out/sample_detect
  ```
- [ ] **Browser Prepared**: Ready to open `out/sample_detect/incident_report.html`.
- [ ] **VS Code Workspace**: Open to project root with `README.md`, `config/default.yaml`, and `out/sample_detect/` visible.
- [ ] **Terminal Window**: Clear screen (`cls` or `clear`) with readable 16pt font and UTF-8 console output enabled.

---

## Video Timeline & Segment Summary

| Segment | Timestamp | Duration | Section Topic | Primary Action / Visual |
|---|---|---|---|---|
| **1** | **0:00–0:45** | 0:45 | Problem Statement & Objectives | Title slide / Architecture overview |
| **2** | **0:45–1:45** | 1:00 | Architecture & Hybrid Detection | Diagram walkthrough in `README.md` |
| **3** | **1:45–3:00** | 1:15 | S1–S5 Datasets & Feature Math | Inspect `config/default.yaml` & `data/pcaps/` |
| **4** | **3:00–4:30** | 1:30 | Live Detection Execution | Run `detect` on `s2_port_scan.pcap` in terminal |
| **5** | **4:30–5:30** | 1:00 | Artifact Inspection | Open `alerts.json`, `alerts.csv`, and HTML report |
| **6** | **5:30–7:00** | 1:30 | Evaluation & Metrics Transparency | Run `evaluate` CLI; explain incident vs. window recall |
| **7** | **7:00–8:00** | 1:00 | Benchmark, Profiling & Pytest | Run `benchmark` and `pytest tests/ -v` |
| **8** | **8:00–9:00** | 1:00 | Limitations, Evasion & Edge Cases | Review spoofing FN and benign 1% FPR outliers |
| **9** | **9:00–9:30** | 0:30 | Conclusion & Reproducibility | Show `Makefile` and GitHub repository structure |

---

## Detailed Demonstration Script

---

### Segment 1: Problem Statement and Project Objectives
**Timestamp:** `0:00 – 0:45` (45 seconds)  
**Visual Cue:** Show title slide or project header in `README.md`. Webcam or cursor highlighting the project title.  
**Files / Screens:** `README.md` displayed in VS Code or browser.  

#### Spoken Script:
> "Hello everyone. Today I'm presenting SentinelFlow, an explainable hybrid Network Intrusion Detection System built for offline PCAP forensic triage.
>
> In real-world Security Operations Centers, analysts face an acute dilemma. Traditional signature engines like Snort or Suricata rely on rigid rules that miss novel, stealthy zero-day attacks. Conversely, modern machine learning approaches often act as opaque black boxes, raising raw anomaly scores that provide zero forensic context and trigger severe alert fatigue.
>
> SentinelFlow solves this challenge. Our objective is to combine deterministic, protocol-aware heuristic detectors with an unsupervised Isolation Forest trained strictly on benign network traffic. Every alert produced by SentinelFlow delivers actionable, plain-English explanations, z-score-ranked statistical deviations, and direct mappings to the MITRE ATT&CK framework—all executing in user-space without raw-socket or root privileges."

---

### Segment 2: Architecture and Hybrid Rule/ML Approach
**Timestamp:** `0:45 – 1:45` (60 seconds)  
**Visual Cue:** Display the Mermaid pipeline flowchart in `README.md` or `docs/SentinelFlow_Report.md`.  
**Files / Screens:** Scroll to Section 3: "System Architecture and Detection Pipeline".  

#### Spoken Script:
> "Let’s look at the pipeline architecture. 
>
> The system operates in six distinct stages. First, standard PCAP files are ingested in user-space using Scapy's streaming reader. We decode Layer 2 to Layer 4 headers—extracting MACs, IPs, ports, protocols, and TCP control flags.
>
> Second, the feature extraction module aggregates traffic into non-overlapping 5-second windows partitioned by source IP, while concurrently tracking bidirectional 5-tuple flow states.
>
> Third, these windows enter our dual-engine detection layer. On one side, deterministic rules evaluate protocol thresholds for Port Scans, SYN Floods, UDP Floods, SSH Brute Force, and ARP Spoofing. In parallel, an unsupervised Isolation Forest scores each window for multi-dimensional statistical deviations.
>
> Fourth, our hybrid fusion layer correlates both engines. It coalesces contiguous alert windows from the same source IP into single events, calculates a composite severity score from 0 to 100, and assigns qualitative confidence tiers: HIGH when rule and ML agree, MEDIUM for strong single-engine triggers, and LOW for marginal ML anomalies.
>
> Finally, every alert is enriched with MITRE ATT&CK tactics, techniques, and remediation recommendations."

---

### Segment 3: S1–S5 Synthetic Traffic Scenarios & Feature Extraction
**Timestamp:** `1:45 – 3:00` (75 seconds)  
**Visual Cue:** Open VS Code explorer to `data/pcaps/` and view `config/default.yaml`.  
**Files / Screens:** `config/default.yaml` and directory listing of `data/pcaps/`.  

#### Spoken Script:
> "To guarantee safe, fully reproducible testing without transmitting live malicious traffic across public networks, SentinelFlow includes a synthetic PCAP generator with fixed random seeds. 
>
> We benchmark across five comprehensive scenarios encompassing ten captures:
> - Scenario 1 is our Benign Baseline, containing legitimate HTTP, DNS, SSH, and ICMP telemetry. Crucially, our Isolation Forest model is trained *exclusively* on this capture.
> - Scenario 2 models Reconnaissance: a fast TCP SYN port scan across 100 ports, and a low-and-slow stealth scan.
> - Scenario 3 simulates Denial of Service: high-rate SYN floods, randomized spoofed-source SYN floods, and UDP datagram storms.
> - Scenario 4 models Exploitation: automated SSH credential brute forcing on port 22, and Layer 2 ARP cache poisoning.
> - Scenario 5 introduces real-world discrimination challenges: a high-volume legitimate backup transfer using rsync, and a distributed slow scan.
>
> Over 5-second windows, we compute 12 statistical features: volumetric rates, handshake dynamics like the SYN-to-ACK ratio, and structural diversity like unique destination ports. We also correlate TCP handshakes across bidirectional flows to avoid false-positive connection failures when responses fall into different source windows."

---

### Segment 4: Live Detection Execution
**Timestamp:** `3:00 – 4:30` (90 seconds)  
**Visual Cue:** Switch to terminal window. Ensure prompt is clean.  
**Terminal Command:**
```bash
python -m sentinelflow.cli detect data/pcaps/s2_port_scan.pcap --mode hybrid --out out/sample_detect
```

#### Spoken Script:
> "Now let's run the detection engine live from the CLI.
>
> We execute: `python -m sentinelflow.cli detect data/pcaps/s2_port_scan.pcap --mode hybrid --out out/sample_detect`.
>
> *(Allow command to run and display the Rich terminal table)*
>
> Notice what just happened in under 30 seconds. The parser ingested 3,912 packets and extracted 432 traffic windows.
>
> The terminal output presents a structured security incident summary:
> Here, `192.168.1.99` is flagged with HIGH confidence for a Port Scan attack targeting `192.168.1.20`. It is mapped to MITRE ATT&CK Technique T1046: Network Service Discovery, with a composite severity of 64 out of 100 spanning 4 coalesced windows.
>
> Notice that the Isolation Forest also independently flagged statistical anomalies from the target host's response traffic at LOW confidence.
>
> The CLI exports three investigation artifacts to our output directory: `alerts.json`, `alerts.csv`, and a self-contained `incident_report.html`."

---

### Segment 5: Inspecting Investigation Artifacts
**Timestamp:** `4:30 – 5:30` (60 seconds)  
**Visual Cue:** Open `out/sample_detect/alerts.json` in VS Code, then open `out/sample_detect/incident_report.html` in Chrome/Firefox.  
**Files / Screens:** `out/sample_detect/alerts.json` and browser rendering of `incident_report.html`.  

#### Spoken Script:
> "Let's inspect the exported forensic artifacts.
>
> In `alerts.json`, each incident adheres to our explainability schema contract. Notice the `matched_conditions` array: it explicitly records that destination port diversity hit 233, exceeding our threshold of 20, and that 100% of SYN handshakes were unanswered. 
>
> Even more powerful is the `top_deviating_features` dictionary. Rather than an uninterpretable score, SentinelFlow calculates feature z-scores relative to the benign baseline: unique destination ports deviated by +544 standard deviations, and SYN count deviated by +729 standard deviations!
>
> Now, switching to the browser, here is `incident_report.html`. 
>
> It provides a dark-mode incident dashboard for SOC analysts. At the top, KPI summary cards display total incidents, highest severity, and MITRE tactics. Below, each incident is broken down into structured evidence blocks, complete with plain-English summaries, baseline comparison graphs, and concrete analyst remediation recommendations."

---

### Segment 6: Evaluation Results & Metrics Transparency
**Timestamp:** `5:30 – 7:00` (90 seconds)  
**Visual Cue:** Return to terminal and run the evaluation command. Display the resulting evaluation table.  
**Terminal Command:**
```bash
python -m sentinelflow.cli evaluate --pcaps-dir data/pcaps --mode hybrid
```

#### Spoken Script:
> "Now let's examine our quantitative benchmark evaluation. 
>
> We run `python -m sentinelflow.cli evaluate --pcaps-dir data/pcaps --mode hybrid`.
>
> *(Wait for evaluation table to render)*
>
> SentinelFlow evaluates detection performance at two distinct levels:
> First, at the **Incident / Scenario Level**:
> Across all 10 captures, SentinelFlow achieves **100% Recall, 80% Precision, and an 88.89% F1-score**. Every single attack scenario (S2 through S5) was successfully detected with zero false negatives. The two false positives stem from the benign baseline and flash crowd captures triggering low-confidence ML outliers.
>
> Second, look at the **Window Level** metrics:
> Precision is 28.95%, but Recall is 0.43%. Why does this divergence occur?
>
> We must be completely transparent about this: in our spoofed SYN flood scenario, `s3_syn_flood_spoofed.pcap`, the attacker generates thousands of randomized source IP addresses. Because feature extraction partitions windows per source IP, this produces over 4,900 separate 5-second window slices. 
>
> While ground truth marks every ephemeral window as malicious, each spoofed IP only sends 1 or 2 packets before vanishing. A source sending two packets does not hit our volumetric flood rule of 100 packets per second, nor does it present single-source statistical anomalies. 
>
> SentinelFlow raises aggregate ML alerts that detect the overall attack incident with 100% fidelity, but leaves individual, un-aggregated spoofed windows unflagged, creating over 4,000 window-level false negatives. Understanding this distinction is essential for honest evaluation in NIDS research."

---

### Segment 7: Performance Benchmarking, Pytest & Trade-offs
**Timestamp:** `7:00 – 8:00` (60 seconds)  
**Visual Cue:** Run the benchmark command, followed by the pytest test suite.  
**Terminal Commands:**
```bash
python -m sentinelflow.cli benchmark --pcaps-dir data/pcaps
pytest tests/ -v
```

#### Spoken Script:
> "Next, let’s evaluate execution throughput and resource consumption.
>
> Running `python -m sentinelflow.cli benchmark --pcaps-dir data/pcaps`:
> Our pipeline profiles packet decoding, feature calculation, and detection latency. Across scenarios, pure Python parsing throughput ranges between **80 and 233 packets per second**, with peak memory usage remaining under **8 megabytes RAM**.
>
> This demonstrates a key design trade-off: SentinelFlow is optimized for lightweight, unprivileged user-space execution and batch forensic triage. It is not an inline 10-Gigabit line-rate filter. Inline deployments would require front-end DPDK or eBPF kernel packet capture.
>
> Now, running `pytest tests/ -v`:
> All 40 unit and integration tests pass cleanly in under two and a half minutes—validating protocol math, Isolation Forest z-score explainability, rule merging, and edge cases."

---

### Segment 8: Limitations, Missed Cases & False Positives
**Timestamp:** `8:00 – 9:00` (60 seconds)  
**Visual Cue:** Open `docs/SentinelFlow_Report.md` to Section 10 and Section 12 ("Difficult Cases" and "Limitations").  
**Files / Screens:** Scroll through Section 10 and Section 11 of the report in VS Code.  

#### Spoken Script:
> "Let’s discuss real-world limitations and evasion considerations.
>
> First, **Evasion**: An adversary who scans very slowly—fewer than 1 port every 5 seconds—will stay beneath our deterministic port scan threshold. However, as demonstrated in our slow-scan scenario, the unsupervised Isolation Forest successfully detects the cumulative distributional shift over time.
>
> Second, **Benign Baseline False Positives**: Why did `s1_benign` and `s5_flash_crowd` trigger alerts? 
> We explicitly calibrated our Isolation Forest threshold on a benign validation split to a **1.0% false-positive rate** ($\alpha = 0.01$). Across 424 windows, a 1% FPR mathematically guarantees 2 to 4 statistical tail outliers. In `s5_flash_crowd`, legitimate bulk rsync backups deviate by +6.4 standard deviations from normal browsing.
>
> Third, **Confidence Calibration**: Our confidence tiers (HIGH, MEDIUM, LOW) represent discrete qualitative consensus between rule signatures and anomaly scores, not calibrated Bayesian probabilities.
>
> Future improvements will introduce dual destination-keyed windows for distributed DoS attacks, streaming ring-buffer ingestion, and conformal prediction for formal error bounds."

---

### Segment 9: Summary & Reproducibility
**Timestamp:** `9:00 – 9:30` (30 seconds)  
**Visual Cue:** Show `Makefile` targets, `git status`, and GitHub repository landing view.  
**Files / Screens:** `Makefile` open in editor.  

#### Spoken Script:
> "To summarize: SentinelFlow provides a transparent, explainable hybrid NIDS that bridges the gap between rigid rule engines and black-box ML. It delivers 100% incident recall across our evaluation suite, exports multi-format forensic reports, and adheres to strict software engineering standards.
>
> Every command demonstrated today is reproducible via simple Make targets: `make generate-data`, `make train`, `make detect`, `make evaluate`, and `make test`.
>
> Thank you for your time and consideration."

---

## Post-Recording Verification Checklist

- [ ] Total recorded video length is between **8:00 and 10:00** (ideal target: ~9:30).
- [ ] Spoke clearly with all terminal commands executed live.
- [ ] Showed terminal detection table, `alerts.json`, and browser `incident_report.html`.
- [ ] Transparently explained 80% incident precision / 100% recall vs. 0.43% window recall.
- [ ] Confirmed 40/40 pytest tests passed.
- [ ] Verified audio quality and 1080p video resolution.
