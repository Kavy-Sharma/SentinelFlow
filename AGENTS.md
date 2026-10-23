# AGENTS.md — SentinelFlow Project Context & Guidelines

## 1. Project Overview & Purpose
**SentinelFlow** is an explainable hybrid Network Intrusion Detection System (NIDS) designed for a cybersecurity internship take-home assessment. It ingests packet capture (PCAP) files, extracts statistical flow and windowed traffic features, and detects malicious behavior using a hybrid architecture of deterministic signature/rule-based heuristics alongside an unsupervised Isolation Forest trained strictly on benign baseline traffic.

A foundational design requirement is **explainability**: every detected alert must provide clear, actionable attribution describing *what* occurred, *why* it was flagged, the observed vs. expected thresholds or feature z-score deviations, severity, confidence, and corresponding MITRE ATT&CK technique mapping.

---

## 2. Core Goals
1. **PCAP Ingestion**: Offline parsing and packet extraction from `.pcap` files without requiring root/admin privileges or active promiscuous network capture.
2. **Feature Extraction**:
   - Per-source time-windowed aggregated traffic metrics (e.g., packet rates, SYN/ACK ratios, unique destination port counts).
   - Bidirectional network flow records (5-tuple: source IP, destination IP, source port, destination port, protocol).
3. **Hybrid Detection Engine**:
   - Detect **Port Scans**, **SYN/UDP Floods**, **SSH Brute Force**, and **ARP Spoofing**.
   - Combine rule-based deterministic detectors with an unsupervised **Isolation Forest** anomaly model trained *exclusively on benign baseline traffic*.
   - Fuse rule violations and anomaly scores to prioritize high-fidelity threats.
4. **Explainable Alerting & Presentation**:
   - Rich explanations: trigger conditions, observed metrics, statistical deviations (z-scores), MITRE ATT&CK classification.
   - Dual interface: ergonomic Typer CLI and an interactive Streamlit analytics dashboard.

---

## 3. Technology Stack & Constraints

### Environment & Dependencies
- **Language**: Python 3.11.
- **Approved Libraries (Free / Open-Source Only)**:
  - Network parsing: `scapy`
  - Data manipulation & math: `pandas`, `numpy`
  - Machine learning & serialization: `scikit-learn`, `joblib`
  - Visualization & UI: `streamlit`, `plotly`
  - CLI: `typer` (with `rich` if bundled/standard)
  - Testing: `pytest`
  - Configuration: `pyyaml`
- **Strictly Disallowed**: Proprietary, closed-source, or paid SDKs/APIs; network sniffers requiring raw socket root privileges in production flows.

### Operational & Security Constraints
- **Unprivileged Execution**: All scripts, parsers, and services must run entirely in user-space without `root` or `sudo` privileges.
- **Reproducibility**: Enforce deterministic outcomes using fixed random seeds across all ML training, evaluation, and data generation tasks (e.g., `seed: 42`).
- **Ethical & Safe Data Handling**: All attack PCAPs and malicious samples must be synthetic or collected strictly inside isolated, personally owned lab environments. No live attacks or non-consensual scanning tools.

---

## 4. Repository Layout

```text
sentinelflow/
├── sentinelflow/
│   ├── generator/           # Synthetic benign & attack traffic/PCAP generators
│   ├── parser.py            # PCAP ingestion, packet parsing, protocol filtering
│   ├── features.py          # Time-window aggregations & bidirectional flow extraction
│   ├── rules.py             # Rule-based threat detectors (Port scan, Flood, Brute force, ARP)
│   ├── ml.py                # Isolation Forest training, scoring & feature deviation (z-score)
│   ├── fusion.py            # Hybrid alert fusion & score arbitration
│   ├── attack_map.py        # MITRE ATT&CK framework mapping & metadata
│   ├── evaluate.py          # Benchmark metrics (Precision, Recall, F1, ROC-AUC, confusion matrix)
│   ├── benchmark.py         # Performance, throughput, and latency profiling
│   └── cli.py               # Typer CLI commands (ingest, train, detect, evaluate)
├── app/
│   └── dashboard.py         # Interactive Streamlit investigation dashboard
├── config/
│   └── default.yaml         # Centralized hyperparameters, thresholds, and paths
├── tests/                   # Pytest suite (unit, integration, and golden dataset tests)
├── notebooks/               # Exploratory data analysis and model verification
├── docs/                    # Architecture diagrams, design rationale, and evaluation reports
├── data/                    # Local storage for raw PCAPs, processed flows, and model artifacts
├── AGENTS.md                # Agent instructions & persistent context (this file)
└── README.md                # Project documentation and quickstart instructions
```

---

## 5. Coding Standards & Conventions

### Style & Quality
- **Type Annotations**: Mandatory type hints on all function parameters, return values, and module-level constants.
- **Docstrings**: Google or Sphinx-style docstrings for every class, public method, and module, specifying arguments, return types, and exceptions.
- **Modularity & Granularity**: Write short, single-purpose functions. Avoid monolithic blocks or functions exceeding ~50 lines where separation of concerns is feasible.
- **Logging**: Use Python's standard `logging` module exclusively. **Never use `print()`** in library or detection code (CLI commands should output via Typer/Rich or logger).
- **Configuration & Paths**:
  - All detector thresholds, model parameters, and window sizes must reside in `config/default.yaml`.
  - **No hard-coded absolute or relative string paths**. Use `pathlib.Path` resolved relative to project roots or configuration settings.

---

## 6. Alert & Explainability Schema (Data Contract)

Every detection—whether triggered by a heuristic rule, an ML anomaly, or the hybrid fusion layer—must produce a structured alert record adhering to this schema:

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class AlertExplanation:
    rule_id: str                              # e.g., "RULE-SCAN-001" or "ML-IFOREST-ANOMALY"
    detector_name: str                        # Human-readable detector title
    matched_conditions: List[str]             # Boolean conditions satisfied
    observed_values: Dict[str, Any]           # Extracted metrics (e.g., {"syn_rate": 250.4})
    thresholds: Dict[str, Any]                # Expected thresholds (e.g., {"syn_rate_limit": 100.0})
    anomaly_score: float                      # Normalized anomaly score (0.0 to 1.0 or raw decision value)
    top_deviating_features: Dict[str, float]  # Top features ranked by z-score deviation vs. baseline
    severity: int                             # Integer score between 0 and 100
    confidence: ConfidenceLevel               # HIGH, MEDIUM, or LOW
    mitre_technique_id: str                   # e.g., "T1046"
    mitre_technique_name: str                 # e.g., "Network Service Discovery"
    mitre_tactic: str                         # e.g., "Discovery"
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    timestamp: Optional[float] = None
    summary: str = ""
```

---

## 7. Attack Coverage & MITRE ATT&CK Mappings

| Attack Vector | Detector Strategy | MITRE Technique ID | MITRE Technique Name | MITRE Tactic |
|---|---|---|---|---|
| **Port Scan** (TCP SYN, Full Connect) | Destination port diversity / time window | `T1046` | Network Service Discovery | Discovery |
| **SYN Flood** | High SYN rate, unbalanced SYN/ACK ratio | `T1498.001` | Network Denial of Service: Direct Network Flood | Impact |
| **UDP Flood** | Sudden packet rate surge on unestablished UDP ports | `T1498.001` | Network Denial of Service: Direct Network Flood | Impact |
| **SSH Brute Force** | High frequency of small-payload TCP/22 sessions | `T1110.001` | Brute Force: Password Guessing | Credential Access |
| **ARP Spoofing** | Multiple MACs claiming identical IP / unsolicited replies | `T1557.002` | Adversary-in-the-Middle: ARP Poisoning | Credential Access / Collection |
| **Unknown Anomaly** | Isolation Forest on baseline deviations | `T1205` / `T1071` | Traffic Anomaly / Non-Standard Protocol Communication | Command and Control / Defense Evasion |

---

## 8. Verification & Workflows

### Testing & Verification
- Unit and integration tests must run via `pytest tests/`.
- Ensure tests validate deterministic outcomes, edge-case PCAP handling (malformed packets, zero-length files), and explainability contracts.

### CLI & UI Entrypoints
- CLI should provide unified subcommands via Typer:
  - `python -m sentinelflow.cli ingest <pcap_path>`
  - `python -m sentinelflow.cli train --config config/default.yaml`
  - `python -m sentinelflow.cli detect <pcap_path>`
  - `python -m sentinelflow.cli evaluate --test-pcap <path>`
  - `python -m sentinelflow.cli benchmark`
- Streamlit application launched via:
  - `streamlit run app/dashboard.py`
