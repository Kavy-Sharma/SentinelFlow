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

## Quickstart & Workflows

Once installed, use the Typer CLI or the Streamlit web dashboard:

```bash
# View available CLI commands
sentinelflow --help

# Generate synthetic lab PCAPs
python -m sentinelflow.generator

# Train benign baseline Isolation Forest
python -m sentinelflow.cli train --config config/default.yaml

# Run detection on a target PCAP
python -m sentinelflow.cli detect data/raw/sample.pcap

# Evaluate performance metrics
python -m sentinelflow.cli evaluate --test-pcap data/raw/eval.pcap

# Launch the Streamlit dashboard
streamlit run app/dashboard.py
```

Or use the provided `Makefile`:

```bash
make setup
make test
make dashboard
```

---

## Testing

Run the test suite with pytest:

```bash
pytest tests/ -v
```

---

## Contributing & Project Standards

Please refer to [AGENTS.md](AGENTS.md) for full architectural guidelines, explainability schema contracts, coding conventions, and security constraints.
