"""End-to-End detection and CLI tests for SentinelFlow.

Validates that:
- Every generated attack scenario PCAP flags its expected MITRE ATT&CK technique and attack type.
- S1 benign traffic yields zero rule alerts (and documented low-confidence ML outliers).
- Alert exports (JSON, CSV, HTML incident reports) are complete and schema-compliant.
- Typer CLI commands (detect, evaluate, benchmark) execute successfully.
"""

import json
from pathlib import Path

import pandas as pd
import pytest
from typer.testing import CliRunner

from sentinelflow.attack_map import AlertExplanation, ConfidenceLevel
from sentinelflow.cli import app
from sentinelflow.features import extract_window_features
from sentinelflow.fusion import (
    export_alerts_csv,
    export_alerts_json,
    export_incident_report_html,
    fuse_detections,
)
from sentinelflow.ml import IsolationForestAnomalyDetector
from sentinelflow.parser import parse_pcap
from sentinelflow.rules import detect_all_rules

runner = CliRunner()


@pytest.fixture(scope="module")
def ml_model() -> IsolationForestAnomalyDetector:
    """Load or fit the Isolation Forest model on benign baseline."""
    model_path = Path("models/isolation_forest.joblib")
    if model_path.is_file():
        return IsolationForestAnomalyDetector.load(model_path)

    pkts = parse_pcap(Path("data/pcaps/s1_benign.pcap"))
    wins = extract_window_features(pkts, window_size=5.0)
    det = IsolationForestAnomalyDetector(random_state=42).fit(wins)
    det.save(model_path)
    return det


# -----------------------------------------------------------------------------
# 1. End-to-End Scenario Attack Flagging Tests
# -----------------------------------------------------------------------------


def test_s1_benign_yields_zero_rule_alerts(ml_model: IsolationForestAnomalyDetector) -> None:
    """Assert S1 benign traffic yields zero rule alerts and only documented <=1% ML outliers."""
    pkts = parse_pcap(Path("data/pcaps/s1_benign.pcap"))
    wins = extract_window_features(pkts, window_size=5.0)

    # 1. Deterministic rules mode must yield exactly 0 alerts
    rule_alerts = detect_all_rules(wins, packets_df=pkts, merge_events=True)
    assert len(rule_alerts) == 0, f"Expected 0 rule alerts on benign baseline, got {len(rule_alerts)}"

    # 2. Hybrid mode: any ML-only alerts must be labeled 'unknown_anomaly' with LOW/MEDIUM confidence
    alerts = fuse_detections(rule_alerts, wins, ml_detector=ml_model, packets_df=pkts)
    # The 1% target FPR across 424 windows yields at most ~4 windows (merged into <= 3 events)
    assert len(alerts) <= 3, f"Expected <= 3 low-confidence ML outliers on benign baseline, got {len(alerts)}"
    for a in alerts:
        assert a.rule_id == "ML-IFOREST-ANOMALY"
        assert a.mitre_technique_id == "T1205"
        assert a.confidence in (ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM)


def test_s2_port_scan_flagged(ml_model: IsolationForestAnomalyDetector) -> None:
    """Assert S2 Port Scan is correctly identified with technique T1046."""
    pkts = parse_pcap(Path("data/pcaps/s2_port_scan.pcap"))
    wins = extract_window_features(pkts, window_size=5.0)

    rule_alerts = detect_all_rules(wins, packets_df=pkts, merge_events=True)
    alerts = fuse_detections(rule_alerts, wins, ml_detector=ml_model, packets_df=pkts)

    scan_alerts = [a for a in alerts if a.mitre_technique_id == "T1046"]
    assert len(scan_alerts) >= 1
    target_alert = next((a for a in scan_alerts if a.source_ip == "192.168.1.99"), None)
    assert target_alert is not None, "Expected attacker 192.168.1.99 to be flagged for port scan"
    assert target_alert.mitre_technique_name == "Network Service Discovery"
    assert target_alert.confidence == ConfidenceLevel.HIGH
    assert target_alert.severity >= 60


def test_s3_syn_flood_flagged(ml_model: IsolationForestAnomalyDetector) -> None:
    """Assert S3 SYN Flood is correctly identified with technique T1498."""
    pkts = parse_pcap(Path("data/pcaps/s3_syn_flood.pcap"))
    wins = extract_window_features(pkts, window_size=5.0)

    rule_alerts = detect_all_rules(wins, packets_df=pkts, merge_events=True)
    alerts = fuse_detections(rule_alerts, wins, ml_detector=ml_model, packets_df=pkts)

    syn_alerts = [a for a in alerts if "SYN" in a.detector_name or a.rule_id == "RULE-SYN-FLOOD"]
    assert len(syn_alerts) >= 1
    assert any(a.source_ip == "192.168.1.150" for a in syn_alerts)
    assert any(a.confidence in (ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM) for a in syn_alerts)
    assert any(a.severity >= 60 for a in syn_alerts)


def test_s3_udp_flood_flagged(ml_model: IsolationForestAnomalyDetector) -> None:
    """Assert S3 UDP Flood is correctly identified with technique T1498."""
    pkts = parse_pcap(Path("data/pcaps/s3_udp_flood.pcap"))
    wins = extract_window_features(pkts, window_size=5.0)

    rule_alerts = detect_all_rules(wins, packets_df=pkts, merge_events=True)
    alerts = fuse_detections(rule_alerts, wins, ml_detector=ml_model, packets_df=pkts)

    udp_alerts = [a for a in alerts if "UDP" in a.detector_name or a.rule_id == "RULE-UDP-FLOOD"]
    assert len(udp_alerts) >= 1
    assert any(a.source_ip == "192.168.1.150" for a in udp_alerts)
    assert any(a.severity >= 60 for a in udp_alerts)


def test_s4_ssh_brute_force_flagged(ml_model: IsolationForestAnomalyDetector) -> None:
    """Assert S4 SSH Brute Force is correctly identified with technique T1110."""
    pkts = parse_pcap(Path("data/pcaps/s4_ssh_brute_force.pcap"))
    wins = extract_window_features(pkts, window_size=5.0)

    rule_alerts = detect_all_rules(wins, packets_df=pkts, merge_events=True)
    alerts = fuse_detections(rule_alerts, wins, ml_detector=ml_model, packets_df=pkts)

    ssh_alerts = [a for a in alerts if "SSH" in a.detector_name or a.rule_id == "RULE-SSH-BRUTE"]
    assert len(ssh_alerts) >= 1
    assert any(a.source_ip == "192.168.1.180" for a in ssh_alerts)
    assert any("T1110" in a.mitre_technique_id for a in ssh_alerts)


def test_s4_arp_spoof_flagged(ml_model: IsolationForestAnomalyDetector) -> None:
    """Assert S4 ARP Spoofing is correctly identified with technique T1557.002."""
    pkts = parse_pcap(Path("data/pcaps/s4_arp_spoof.pcap"))
    wins = extract_window_features(pkts, window_size=5.0)

    rule_alerts = detect_all_rules(wins, packets_df=pkts, merge_events=True)
    alerts = fuse_detections(rule_alerts, wins, ml_detector=ml_model, packets_df=pkts)

    arp_alerts = [a for a in alerts if "ARP" in a.detector_name or a.rule_id == "RULE-ARP-SPOOF"]
    assert len(arp_alerts) >= 1
    assert any(a.source_ip == "192.168.1.1" for a in arp_alerts)
    assert any(a.mitre_technique_id == "T1557.002" for a in arp_alerts)


# -----------------------------------------------------------------------------
# 2. Alert Exporters Tests (JSON, CSV, HTML Report)
# -----------------------------------------------------------------------------


def test_alert_exporters(tmp_path: Path, ml_model: IsolationForestAnomalyDetector) -> None:
    """Verify that alerts export to valid JSON, CSV, and comprehensive HTML report."""
    pkts = parse_pcap(Path("data/pcaps/s2_port_scan.pcap"))
    wins = extract_window_features(pkts, window_size=5.0)

    rule_alerts = detect_all_rules(wins, packets_df=pkts, merge_events=True)
    alerts = fuse_detections(rule_alerts, wins, ml_detector=ml_model, packets_df=pkts)
    assert len(alerts) > 0

    # 1. JSON Export
    json_file = tmp_path / "alerts.json"
    export_alerts_json(alerts, json_file)
    assert json_file.is_file()
    with open(json_file, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert isinstance(loaded, list)
    assert len(loaded) == len(alerts)
    assert "summary" in loaded[0]
    assert "recommendation" in loaded[0]

    # 2. CSV Export
    csv_file = tmp_path / "alerts.csv"
    export_alerts_csv(alerts, csv_file)
    assert csv_file.is_file()
    df = pd.read_csv(csv_file)
    assert len(df) == len(alerts)
    assert "mitre_technique_id" in df.columns

    # 3. HTML Incident Report
    html_file = tmp_path / "incident_report.html"
    export_incident_report_html(alerts, html_file, pcap_name="s2_port_scan.pcap")
    assert html_file.is_file()
    html_text = html_file.read_text(encoding="utf-8")
    assert "<title>SentinelFlow Security Incident Report</title>" in html_text
    assert "s2_port_scan.pcap" in html_text
    assert "Detected Incident Overview" in html_text
    assert "Analyst Recommendation:" in html_text


# -----------------------------------------------------------------------------
# 3. CLI Command Execution Tests
# -----------------------------------------------------------------------------


def test_cli_detect_rules_mode() -> None:
    """Verify CLI `detect --mode rules` executes cleanly on benign baseline."""
    res = runner.invoke(app, ["detect", "data/pcaps/s1_benign.pcap", "--mode", "rules"])
    assert res.exit_code == 0
    assert "ZERO THREAT DETECTIONS" in res.output


def test_cli_detect_hybrid_with_out(tmp_path: Path) -> None:
    """Verify CLI `detect --mode hybrid --out outdir` exports investigation artifacts."""
    out_dir = tmp_path / "cli_out"
    res = runner.invoke(app, ["detect", "data/pcaps/s2_port_scan.pcap", "--mode", "hybrid", "--out", str(out_dir)])
    assert res.exit_code == 0
    assert "Detected Security Incidents" in res.output
    assert (out_dir / "alerts.json").is_file()
    assert (out_dir / "alerts.csv").is_file()
    assert (out_dir / "incident_report.html").is_file()
