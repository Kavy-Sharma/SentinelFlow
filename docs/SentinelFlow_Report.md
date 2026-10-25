# SentinelFlow: Explainable Hybrid Network Intrusion Detection System
## Technical Evaluation & Architectural Assessment Report

**Author:** Cybersecurity Engineering Assessment Team | **Version:** v1.0.0-rc1 | **Target:** Python 3.11 User-Space | **Date:** October 2026

---

## 1. Abstract

Modern Security Operations Centers (SOCs) struggle with signature blind spots and uninterpretable machine learning (ML) alerts. **SentinelFlow** is an explainable hybrid Network Intrusion Detection System (NIDS) for offline packet capture (PCAP) triage. It pairs deterministic heuristics with an unsupervised Isolation Forest trained strictly on benign baseline traffic. Operating on 5-second windowed statistics and bidirectional flow states, SentinelFlow detects threats while generating plain-English, z-score-ranked feature attributions mapped to MITRE ATT&CK techniques.

Across synthetic benchmark scenarios (S1–S5), SentinelFlow achieves 80.00% precision, 100.00% recall, and 88.89% F1-score at the incident level on primary and holdout datasets. At 5-second window resolution, recall is 0.43% with 28.95%–34.55% precision due to spoofed source dispersion. This report explains this divergence, discloses synthetic baseline training, clarifies that confidence scores reflect heuristic concordance rather than calibrated probabilities, and analyzes inline latency, throughput, evasion, and scalability.

---

## 2. Problem Statement and Objectives

Enterprise defense requires accurate and contextually interpretable detection of malicious network traffic. Security analysts investigating PCAP dumps need tools that operate in user-space without raw sockets, respect computational constraints, and deliver structured forensic explanations rather than opaque scores.

SentinelFlow fulfills five core objectives:
1. **Unprivileged Ingestion**: Ingest standard `.pcap` files in user-space without raw sockets or root privileges.
2. **Deterministic Detection**: Identify port scans, SYN/UDP floods, SSH brute force, and ARP spoofing via protocol threshold logic.
3. **Unsupervised Anomaly Profiling**: Model benign communication with an Isolation Forest calibrated to a 1.0% target false-positive rate (FPR) without exposure to attack labels.
4. **Actionable Explainability**: Generate structured explanations highlighting observed metrics, threshold bounds, baseline z-scores ($\sigma$), and MITRE ATT&CK mappings.
5. **Reproducibility**: Enforce fixed seeds, declarative YAML configuration, 100% test pass rate, a Typer CLI, and a Streamlit dashboard.

---

## 3. System Architecture and Detection Pipeline

SentinelFlow implements a modular Python 3.11 pipeline flowing from packet ingestion through feature extraction, parallel heuristic and anomaly detection, hybrid arbitration, and incident reporting.

```mermaid
flowchart TD
    A["Raw PCAP File"] --> B["Packet Parser"]
    B --> C["Protocol Decoding"]
    C --> D["Feature Extractor"]
    D --> E["5s Time Windows"]
    D --> F["Bidirectional Flows"]
    E --> G["Rule Engine"]
    B --> G
    E --> H["Isolation Forest ML"]
    G --> I["Rule Alerts"]
    H --> J["Anomaly Scores & Z-Scores"]
    I --> K["Hybrid Fusion Layer"]
    J --> K
    K --> L["Event Deduplication & Merging"]
    L --> M["MITRE ATT&CK Mapping"]
    M --> N["Alert Artifacts (JSON, CSV, HTML)"]
```

The pipeline executes in six sequential stages: (1) **Packet Parsing (`parser.py`)** extracts Layer 2–4 headers and TCP flags via `scapy.PcapReader`; (2) **Feature Extraction (`features.py`)** computes 5.0s windowed traffic metrics per source IP and tracks bidirectional 5-tuple flows; (3) **Deterministic Detection (`rules.py`)** evaluates thresholds in `config/default.yaml`; (4) **Machine Learning (`ml.py`)** scores standardized features using an Isolation Forest trained on benign baseline traffic; (5) **Hybrid Fusion (`fusion.py`)** coalesces contiguous alert windows, computes composite severity (0–100), and sets qualitative confidence tiers; and (6) **Reporting (`attack_map.py` & `dashboard.py`)** enriches alerts with MITRE ATT&CK mappings and exports JSON, CSV, and HTML reports.

---

## 4. Dataset Design and Scenarios S1–S5

To guarantee scientific reproducibility without transmitting live malicious traffic, SentinelFlow incorporates a synthetic PCAP generator (`sentinelflow/generator`). Traffic generation employs fixed random seeds (`seed: 42` for primary datasets; `seed: 1337` for holdout evaluation).

The benchmark suite evaluates five primary scenarios (S1–S5) across ten PCAPs:
- **S1 (Benign)**: `s1_benign.pcap` (enterprise HTTP/HTTPS, DNS, SSH, ICMP).
- **S2 (Reconnaissance)**: `s2_port_scan.pcap` (fast SYN scan) and `s2_slow_scan.pcap` (stealth probe).
- **S3 (DoS Floods)**: `s3_syn_flood.pcap` (SYN flood), `s3_syn_flood_spoofed.pcap` (spoofed flood), and `s3_udp_flood.pcap` (UDP storm).
- **S4 (Exploitation)**: `s4_ssh_brute_force.pcap` (port 22 storm) and `s4_arp_spoof.pcap` (gateway poisoning).
- **S5 (Discrimination)**: `s5_flash_crowd.pcap` (rsync backup burst) and `s5_distributed_slow_scan.pcap` (coordinated scan).

*Dataset Disclosure*: All evaluation datasets are synthetic. Training was conducted exclusively on `s1_benign.pcap`.

---

## 5. Feature Extraction and Justification

Heuristic thresholding and anomaly detection rely on 12 statistical features computed per source IP across 5.0-second time windows:
- **Volumetric**: `packet_count`, `byte_count`, `packet_rate`, and `byte_rate` quantify transmission intensity and bandwidth consumption to detect DoS flooding.
- **Protocol & Handshake**: `syn_count`, `ack_count`, and `syn_ack_ratio` ($	ext{syn} / (	ext{ack} + 1)$) detect half-open handshake backlogs. `tcp_ratio` and `udp_ratio` isolate protocol anomalies.
- **Diversity**: `unique_dst_ips`, `unique_dst_ports`, and `unique_src_ports` capture network sweeps, port scans, and socket cycling.

SentinelFlow correlates TCP state transitions across bidirectional flows (5-tuples), ensuring SYN and SYN-ACK packets are matched across endpoints even when reverse traffic spans separate source-partitioned windows.

---

## 6. Rule-Based Detection

The deterministic layer (`sentinelflow/rules.py`) applies protocol-aware signatures against window records and raw frame tables using thresholds in `config/default.yaml`:
- **Port Scan (`RULE-PORT-SCAN`, T1046)**: Flags sources querying $\ge 20$ destination ports per 5s window, or exhibiting port diversity $\ge 0.5$ with $\ge 15$ packets.
- **SYN Flood (`RULE-SYN-FLOOD`, T1498.001)**: Triggers when `packet_rate` $\ge 100$ pps, `syn_ack_ratio` $\ge 3.0$, and total SYNs $\ge 50$.
- **UDP Flood (`RULE-UDP-FLOOD`, T1498.001)**: Flags stateless bursts where `packet_rate` $\ge 150$ pps and `udp_ratio` $\ge 0.80$.
- **SSH Brute Force (`RULE-SSH-BRUTE`, T1110.001)**: Requires explicit port 22 evidence, flagging $\ge 5$ connection attempts with mean payload $< 400$ bytes.
- **ARP Spoofing (`RULE-ARP-SPOOF`, T1557.002)**: Flags multiple MACs claiming a single IP or unsolicited ARP replies without prior requests.

---

## 7. Isolation Forest Anomaly Detection

To detect unknown anomalies and slow deviations that evade fixed thresholds, SentinelFlow implements an unsupervised Isolation Forest model (`sentinelflow/ml.py`).

The detector is trained **strictly on benign baseline traffic** (`s1_benign.pcap`), containing 424 extracted 5-second windows. Features are normalized via `StandardScaler`. Rather than using default contamination heuristics, the decision threshold is calibrated to the 99th percentile of benign validation scores, fixing the target false-positive rate at 1.0% ($lpha = 0.01$). This produced an empirical decision threshold of `0.2041`.

For flagged windows, SentinelFlow computes feature z-scores relative to baseline distributions:
$$z_i = \frac{x_i - \mu_{\text{benign}, i}}{\sigma_{\text{benign}, i}}$$
The engine formats the top three deviating features (e.g., `unique_dst_ports +14.2σ`, `packet_rate +8.7σ`), providing analysts with immediate statistical attribution.

---

## 8. Hybrid Fusion, Alert Explanations, Severity, and Confidence

The hybrid fusion layer (`sentinelflow/fusion.py`) reconciles deterministic rule alerts and ML anomaly scores. Contiguous 5-second windows from identical source endpoints and detectors are coalesced into single incident records tracking duration and peak metrics to eliminate alert fatigue.

Severity (0–100) is computed as a weighted composite:
$$\text{Severity} = 0.40 \cdot (\text{Rule Strength} \cdot 100) + 0.35 \cdot (\text{ML Anomaly Score} \cdot 100) + 0.25 \cdot \text{Attack Weight}$$
Binned into Informational (0–20), Low (21–40), Medium (41–70), and High (71–100).

Confidence ratings represent heuristic concordance:
- `HIGH`: Both rule signature and ML model independently flag the activity.
- `MEDIUM`: A rule fires with high margin, or the ML model detects an extreme anomaly ($\ge 0.40$).
- `LOW`: Marginal ML-only anomaly detection without supporting signature violation.

*Statistical Disclosure*: Confidence ratings are discrete qualitative categories reflecting heuristic agreement, not calibrated Bayesian posterior probabilities.

---

## 9. Evaluation Methodology and Results

Evaluation was executed across primary (`data/pcaps`, seed 42) and holdout (`data/pcaps_holdout`, seed 1337) datasets using `sentinelflow.cli evaluate` at two levels: (1) **Incident Level**: Binary classification of whether an entire attack capture is flagged; and (2) **Window Level**: Granular classification of every 5.0-second time slice against ground truth.

All eight attack captures were reliably detected via rule or ML layers. Benign captures (`s1_benign`, `s5_flash_crowd`) raised zero rule alerts, producing low-confidence ML tail outliers consistent with the 1% FPR target.

| Evaluation Level | Dataset | Total Windows | TP | FP | FN | TN | Precision | Recall | Accuracy | F1-Score |
|---|---|---|---|---|---|---|---|---|---|---|
| **Incident-Level** | **Primary (`data/pcaps`)** | 10 captures | 8 | 2 | 0 | 0 | **80.00%** | **100.00%** | **80.00%** | **88.89%** |
| **Incident-Level** | **Holdout (`data/pcaps_holdout`)** | 10 captures | 8 | 2 | 0 | 0 | **80.00%** | **100.00%** | **80.00%** | **88.89%** |
| **Window-Level** | **Primary (`data/pcaps`)** | 9,351 windows | 22 | 54 | 5,044 | 4,231 | **28.95%** | **0.43%** | **45.48%** | **0.86%** |
| **Window-Level** | **Holdout (`data/pcaps_holdout`)** | 8,548 windows | 19 | 36 | 4,351 | 4,142 | **34.55%** | **0.43%** | **48.68%** | **0.86%** |

---

## 10. Difficult Cases, False Positives, and False Negatives

### Explaining Incident-Level vs. Window-Level Divergence
The benchmark exhibits 100.00% incident-level recall alongside 0.43% window-level recall due to spoofed flooding mechanics:
- In `s3_syn_flood_spoofed.pcap`, an attacker generates thousands of randomized source IPs, yielding **4,912 distinct 5-second window slices** in primary and **4,212 slices** in holdout.
- While ground truth labels each slice as malicious, each spoofed IP transmits only 1–2 packets before vanishing. A source sending 2 packets does not exceed volumetric flood thresholds ($\ge 100	ext{ pps}$) nor register single-source statistical anomalies.
- SentinelFlow raises aggregated ML alerts on the capture (achieving 100% incident detection), but leaves un-aggregated spoofed IP slices unflagged, creating over 4,000 statistical false negatives at the window level. Temporal event merging also coalesces adjacent malicious windows into single incident objects.

### Analysis of Benign False Positives (S1 and S5)
In `s1_benign` and `s5_flash_crowd`, the rule engine remained silent (0 rule FPs). However, the Isolation Forest flagged 2 low-confidence anomaly alerts in `s1_benign` and 4 in `s5_flash_crowd`. This is expected: the threshold was calibrated to an intentional **1.0% false-positive rate**, producing 2–4 tail outliers across 424 windows. In `s5_flash_crowd`, volumetric bursts from `rsync` legitimately deviate by $+6.4\sigma$ from baseline browsing, which the model flags as an unclassified anomaly.

---

## 11. Network and Security Considerations

### Inline Latency and Throughput Limits
SentinelFlow is built upon Python and `scapy`. Benchmarking profiles record parsing throughputs between **80 and 233 packets/second**, with memory utilization between 2.8 MB and 7.7 MB RAM. While suitable for offline forensic triage and lab verification, pure Python decoding cannot process live 10 Gbps backbones inline. High-speed inline deployments require hardware capture appliances or DPDK/eBPF pre-filtering.

### Capture Completeness & Packet Drops
Operating offline on PCAPs, SentinelFlow assumes capture completeness. Packet drops that lose TCP control packets (`SYN-ACK` or `RST`) skew the `syn_ack_ratio`, potentially triggering spurious flood alerts.

### Adversarial Evasion
1. **Low-and-Slow Scanning**: Attackers probing fewer than 1 port every 5 seconds evade `RULE-PORT-SCAN`. However, as shown in `s2_slow_scan`, the Isolation Forest captures cumulative distributional shifts.
2. **Spoofed Flooding**: Randomizing source IPs disperses window aggregations. Mitigation requires destination-centric window grouping alongside source grouping.
3. **Encrypted Payloads**: While encryption blinds deep inspection, SentinelFlow relies on unencrypted Layer 3/4 headers, timing, and flow metadata, preserving efficacy against encrypted traffic.

### SOC False-Positive Economics
In an enterprise SOC handling millions of events daily, a 1.0% raw alert rate causes triage fatigue. SentinelFlow downgrades ML-only baseline outliers to `LOW` confidence and coalesces contiguous events, allowing analysts to filter on `HIGH` and `MEDIUM` confidence alerts during initial triage.

---

## 12. Limitations and Future Work

1. **Source-Centric Partitioning**: Partitioning windows solely by source IP limits visibility into distributed DoS and spoofed attacks. Dual destination-keyed windows are planned.
2. **Offline vs. Streaming Execution**: The engine requires completed PCAP files. Transitioning to a sliding ring-buffer architecture will enable continuous streaming triage.
3. **Heuristic Confidence**: Future iterations should incorporate conformal prediction to provide mathematically rigorous error bounds.
4. **Deep Packet Inspection (DPI)**: Incorporating protocol parsers for DNS tunneling and TLS certificate anomalies will broaden threat coverage beyond Layer 3/4 transport metrics.

---

## 13. Reproducibility and How to Run

SentinelFlow enforces full reproducibility across Python 3.11 environments:

```bash
python -m venv .venv && source .venv/bin/activate  # (or .\.venv\Scripts\Activate.ps1 on Windows)
pip install -r requirements.txt && pip install -e .
python -m sentinelflow.generator --scenario all --seed 42 --out data/pcaps --generate-holdout
python -m sentinelflow.cli train --benign data/pcaps/s1_benign.pcap --out models/isolation_forest.joblib
python -m sentinelflow.cli detect data/pcaps/s2_port_scan.pcap --mode hybrid --out out/sample_detect
python -m sentinelflow.cli evaluate --pcaps-dir data/pcaps --mode hybrid
python -m sentinelflow.cli evaluate --pcaps-dir data/pcaps_holdout --mode hybrid
python -m sentinelflow.cli benchmark --pcaps-dir data/pcaps
pytest tests/ -v
```

All workflows are also executable via Makefile targets (`make setup`, `make generate-data`, `make train`, `make detect`, `make evaluate`, `make benchmark`, `make test`).
