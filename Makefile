.PHONY: help setup generate-data detect evaluate dashboard test clean

PYTHON ?= python

help:
	@echo "SentinelFlow Development Makefile"
	@echo "---------------------------------"
	@echo "Targets:"
	@echo "  setup         : Install package and dependencies in editable mode"
	@echo "  generate-data : Generate synthetic benign baseline and attack PCAPs"
	@echo "  detect        : Execute hybrid detection engine on sample PCAP"
	@echo "  evaluate      : Evaluate detection accuracy against labeled evaluation datasets"
	@echo "  dashboard     : Launch interactive Streamlit analysis dashboard"
	@echo "  test          : Run test suite with pytest"
	@echo "  clean         : Remove build artifacts and cache files"

setup:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -e .

generate-data:
	$(PYTHON) -m sentinelflow.generator --scenario all --seed 42 --out data/pcaps --generate-holdout

detect:
	$(PYTHON) -m sentinelflow.cli detect data/raw/sample.pcap

evaluate:
	$(PYTHON) -m sentinelflow.cli evaluate --test-pcap data/raw/eval.pcap

dashboard:
	streamlit run app/dashboard.py

test:
	pytest tests/

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf build dist *.egg-info .pytest_cache
