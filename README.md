# SentinelFlow: Explainable Hybrid Network Intrusion Detection System

SentinelFlow is an explainable hybrid Network Intrusion Detection System (NIDS) designed for network security triage and offline PCAP analysis. It pairs deterministic rule-based heuristic detectors with an unsupervised Isolation Forest trained strictly on benign baseline traffic, delivering structured and actionable explainability with MITRE ATT&CK technique mapping.

---

## Architecture Overview

- **PCAP Ingestion & Parsing (`parser.py`)**: Offline packet extraction and protocol filtering without raw socket or root permissions.
- **Feature Extraction (`features.py`)**: Computes bidirectional flow records and per-source time-windowed aggregated traffic statistics.
- **Rule Engine (`rules.py`)**: Deterministic signatures for Port Scans, SYN Floods, UDP Floods, SSH Brute Force, and ARP Spoofing.
- **ML Anomaly Detection (`ml.py`)**: Unsupervised Isolation Forest baseline model with z-score deviation rankings for anomaly explainability.
- **Alert Fusion (`fusion.py`)**: Correlates heuristic and anomaly detections, escalating confidence and prioritizing alerts.
- **Interactive Dashboard (`app/dashboard.py`)**: Streamlit analytical interface for alert inspection and feature triage.

---

## Environment Setup

SentinelFlow requires **Python 3.11**. Follow the instructions below to configure an isolated virtual environment:

### Windows (PowerShell)

```powershell
# 1. Create a virtual environment
python -m venv .venv

# 2. Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# (Optional: if script execution is restricted)
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 3. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Install SentinelFlow in editable mode
pip install -e .
```

### Windows (Command Prompt `cmd.exe`)

```cmd
python -m venv .venv
.\.venv\Scripts\activate.bat
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

### Linux & macOS (Bash / Zsh)

```bash
# 1. Create a virtual environment
python3 -m venv .venv

# 2. Activate the virtual environment
source .venv/bin/activate

# 3. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Install SentinelFlow in editable mode
pip install -e .
```

---

## Configuration

All detector thresholds, time-window intervals, ML hyperparameters, and dataset paths are centrally defined in `config/default.yaml`. Modify parameters there to tune sensitivity or feature extraction windows.

---

---

## Quickstart & Workflows

SentinelFlow provides a unified CLI via Typer (executable with `python -m sentinelflow.cli` or `sentinelflow` when installed).

### 1. Reproducible Dataset Generation (S1–S5 Scenarios)
Synthesize benign background traffic and targeted attack overlays with fixed seeds:

```bash
# Generate primary datasets (data/pcaps, seed 42) and holdout captures (data/pcaps_holdout, seed 1337)
python -m sentinelflow.generator --scenario all --seed 42 --out data/pcaps --generate-holdout
```

Generated scenarios include:
- `s1_benign.pcap`: Enterprise background mix (HTTP/HTTPS, DNS, SSH, ICMP).
- `s2_port_scan.pcap` & `s2_slow_scan.pcap`: Fast SYN scan and slow stealth probe.
- `s3_syn_flood.pcap`, `s3_syn_flood_spoofed.pcap`, `s3_udp_flood.pcap`: DoS floods + `victim_metrics.csv`.
- `s4_ssh_brute_force.pcap` & `s4_arp_spoof.pcap`: Credential guessing and Gateway ARP MitM.
- `s5_flash_crowd.pcap` & `s5_distributed_slow_scan.pcap`: Legitimate backup transfer and distributed stealth scan.

---

### 2. Train Benign Baseline Model
Train an unsupervised Isolation Forest strictly on benign baseline traffic:

```bash
# Train Isolation Forest with 1% target FPR threshold calibration
python -m sentinelflow.cli train --benign data/pcaps/s1_benign.pcap --out models/isolation_forest.joblib
```

---

### 3. Threat Detection & Incident Report Export
Analyze a PCAP capture using the hybrid detection engine and export investigation artifacts:

```bash
# Execute hybrid detection and export JSON, CSV, and HTML incident report
python -m sentinelflow.cli detect data/pcaps/s2_port_scan.pcap --mode hybrid --out out/sample_detect
```

Detection Modes (`--mode` / `-m`):
- `hybrid`: Fuses deterministic rule violations with ML anomaly scoring and MITRE ATT&CK attribution (**default & recommended**).
- `rules`: Deterministic heuristic signatures only.
- `ml`: Unsupervised Isolation Forest anomaly scoring only.

Exported Artifacts in `out/`:
- `alerts.json`: Machine-readable alert records adhering to SentinelFlow's explainability schema.
- `alerts.csv`: Tabular alert log for spreadsheet triage.
- `incident_report.html`: Self-contained HTML report with KPI metric cards, threat summaries, and event evidence sections.

---

### 4. Benchmark & Accuracy Evaluation
Compute confusion matrix metrics (TP, FP, FN, TN, Precision, Recall, Accuracy, F1-Score) across labeled captures:

```bash
# Evaluate detection engine on primary captures
python -m sentinelflow.cli evaluate --pcaps-dir data/pcaps --mode hybrid

# Evaluate generalization on independent holdout captures
python -m sentinelflow.cli evaluate --pcaps-dir data/pcaps_holdout --mode hybrid
```

The evaluator reports performance at both:
1. **Incident / Scenario Level**: Binary capture-level classification.
2. **Window Level**: Fine-grained 5-second time-window entity and temporal attribution.

---

### 5. Throughput, Latency & Memory Profiling
Profile parsing throughput, extraction latency, and memory consumption:

```bash
# Profile packet parsing throughput (pps, MB/s) and peak RAM
python -m sentinelflow.cli benchmark --pcaps-dir data/pcaps
```

---

### 6. Interactive Investigation Dashboard
Launch the visual Streamlit analysis dashboard:

```bash
streamlit run app/dashboard.py
```

---

## Makefile Automation

All primary workflows are available via `make`:

```bash
make setup          # Install dependencies in editable mode
make generate-data  # Regenerate S1-S5 primary and holdout PCAPs
make train          # Train benign baseline Isolation Forest
make detect         # Run detection on sample port scan PCAP and export report
make evaluate       # Run dual-level evaluation across labeled datasets
make benchmark      # Profile throughput, latency, and peak memory
make test           # Run full pytest test suite
make clean          # Remove caches, build artifacts, and test exports
```

---

## Testing

Run the automated test suite with pytest:

```bash
# Run all 40 unit, integration, and golden tests
pytest tests/ -v
```

---

## Contributing & Project Standards

Please refer to [AGENTS.md](AGENTS.md) for architectural guidelines, explainability schema contracts, coding conventions, and security constraints.

