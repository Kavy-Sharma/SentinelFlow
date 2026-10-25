.PHONY: help setup generate-data train detect evaluate benchmark dashboard test clean

PYTHON ?= python

help:
	@echo "SentinelFlow Development Makefile"
	@echo "---------------------------------"
	@echo "Targets:"
	@echo "  setup         : Install package and dependencies in editable mode"
	@echo "  generate-data : Generate synthetic benign baseline and attack PCAPs (S1-S5 + holdout)"
	@echo "  train         : Train benign baseline Isolation Forest model"
	@echo "  detect        : Execute hybrid detection engine on sample PCAP and export report"
	@echo "  evaluate      : Evaluate detection accuracy across labeled evaluation datasets"
	@echo "  benchmark     : Profile PCAP parsing throughput, latency, and memory consumption"
	@echo "  dashboard     : Launch interactive Streamlit analysis dashboard"
	@echo "  test          : Run test suite with pytest"
	@echo "  clean         : Remove build artifacts, cache files, and test exports"

setup:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -e .

generate-data:
	$(PYTHON) -m sentinelflow.generator --scenario all --seed 42 --out data/pcaps --generate-holdout

train:
	$(PYTHON) -m sentinelflow.cli train --benign data/pcaps/s1_benign.pcap --out models/isolation_forest.joblib

detect:
	$(PYTHON) -m sentinelflow.cli detect data/pcaps/s2_port_scan.pcap --mode hybrid --out out/sample_detect

evaluate:
	$(PYTHON) -m sentinelflow.cli evaluate --pcaps-dir data/pcaps --mode hybrid

benchmark:
	$(PYTHON) -m sentinelflow.cli benchmark --pcaps-dir data/pcaps

dashboard:
	streamlit run app/dashboard.py

test:
	pytest tests/ -v

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf build dist *.egg-info .pytest_cache out/

