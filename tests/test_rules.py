"""Unit tests for sentinelflow.rules and sentinelflow.tune using synthetic feature rows.

Tests:
- Port Scan detector positive and negative cases
- SYN Flood detector positive and negative cases
- UDP Flood detector positive and negative cases
- SSH Brute Force detector positive and negative cases
- ARP Spoofing detector positive and negative cases
- Merging adjacent window alerts into consolidated incident events
- Unified detect_all_rules pipeline
- Threshold sweep tuning on benign baseline features
- Conversion of Alert to AlertExplanation schema
"""

import pandas as pd
import pytest

from sentinelflow.attack_map import AlertExplanation, ConfidenceLevel
from sentinelflow.rules import (
    Alert,
    detect_all_rules,
    detect_arp_spoofing,
    detect_port_scan,
    detect_ssh_bruteforce,
    detect_syn_flood,
    detect_udp_flood,
    merge_adjacent_alerts,
)
from sentinelflow.tune import sweep_thresholds


def _make_base_window(
    src_ip: str = "192.168.1.10",
    win_start: float = 100.0,
    win_end: float = 105.0,
    **kwargs,
) -> dict:
    """Create a default benign feature dictionary with overrides."""
    base = {
        "win_start": win_start,
        "win_end": win_end,
        "src_ip": src_ip,
        "packet_count": 25,
        "pps": 5.0,
        "bps": 16000.0,
        "bytes_per_sec": 2000.0,
        "unique_dst_ips": 1,
        "unique_dst_ports": 2,
        "syn_count": 1,
        "synack_ratio": 0.5,
        "syn_without_ack_fraction": 0.0,
        "short_connection_fraction": 0.0,
        "connections_to_same_dst_port_max": 1,
        "mean_packet_size": 400.0,
        "std_packet_size": 250.0,
        "tcp_share": 0.8,
        "udp_share": 0.1,
        "icmp_share": 0.05,
        "arp_share": 0.05,
        "inter_arrival_mean": 0.2,
        "inter_arrival_std": 0.1,
        "arp_reply_count": 0,
        "mac_binding_changes": 0,
    }
    base.update(kwargs)
    return base


def test_detect_port_scan_positive_and_negative() -> None:
    """Verify port scan detector triggers on high port diversity and ignores benign hosts."""
    # Positive case: Attacker scanning 60 ports
    pos_row = _make_base_window(
        src_ip="192.168.1.99",
        unique_dst_ports=60,
        tcp_share=0.98,
        syn_without_ack_fraction=0.85,
        pps=30.0,
    )
    # Negative case: Benign client browsing web (ports 80, 443)
    neg_row = _make_base_window(
        src_ip="192.168.1.10",
        unique_dst_ports=2,
        tcp_share=0.85,
        syn_without_ack_fraction=0.0,
    )

    df = pd.DataFrame([pos_row, neg_row])
    alerts = detect_port_scan(df)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "RULE-PORT-SCAN"
    assert alert.src_ip == "192.168.1.99"
    assert alert.mitre_technique_id == "T1046"
    assert alert.mitre_tactic == "Discovery"
    assert alert.observed["unique_dst_ports"] == 60
    assert alert.strength > 0.0
    assert len(alert.matched_conditions) >= 2


def test_detect_syn_flood_positive_and_negative() -> None:
    """Verify SYN flood detector identifies high SYN rates with unacknowledged ratios."""
    # Positive case: Flood of 180 pps with high synack_ratio
    pos_row = _make_base_window(
        src_ip="192.168.1.150",
        pps=180.0,
        packet_count=900,
        syn_count=900,
        tcp_share=1.0,
        synack_ratio=20.0,
        syn_without_ack_fraction=0.95,
    )
    # Negative case: Normal client traffic
    neg_row = _make_base_window(
        src_ip="192.168.1.10",
        pps=8.0,
        syn_count=2,
        synack_ratio=0.66,
        syn_without_ack_fraction=0.0,
    )

    df = pd.DataFrame([pos_row, neg_row])
    alerts = detect_syn_flood(df)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "RULE-SYN-FLOOD"
    assert alert.src_ip == "192.168.1.150"
    assert alert.mitre_technique_id == "T1498.001"
    assert alert.mitre_tactic == "Impact"
    assert alert.observed["synack_ratio"] == 20.0
    assert alert.strength > 0.0


def test_detect_udp_flood_positive_and_negative() -> None:
    """Verify UDP flood detector identifies high UDP rate surges."""
    # Positive case: 220 pps dominated by UDP
    pos_row = _make_base_window(
        src_ip="192.168.1.150",
        pps=220.0,
        packet_count=1100,
        udp_share=0.95,
        tcp_share=0.0,
    )
    # Negative case: Occasional DNS resolution
    neg_row = _make_base_window(
        src_ip="192.168.1.10",
        pps=3.0,
        udp_share=0.2,
        tcp_share=0.7,
    )

    df = pd.DataFrame([pos_row, neg_row])
    alerts = detect_udp_flood(df)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "RULE-UDP-FLOOD"
    assert alert.src_ip == "192.168.1.150"
    assert alert.mitre_technique_id == "T1498.001"
    assert alert.observed["udp_share"] == 0.95


def test_detect_ssh_bruteforce_positive_and_negative() -> None:
    """Verify SSH brute force detector flags repeated connection attempts with short sessions."""
    # Positive case: 18 repeated short sessions to single port
    pos_row = _make_base_window(
        src_ip="192.168.1.180",
        connections_to_same_dst_port_max=18,
        short_connection_fraction=0.88,
        mean_packet_size=240.0,
        tcp_share=0.98,
    )
    # Negative case: Normal single interactive SSH connection
    neg_row = _make_base_window(
        src_ip="192.168.1.10",
        connections_to_same_dst_port_max=1,
        short_connection_fraction=0.0,
        mean_packet_size=120.0,
    )

    df = pd.DataFrame([pos_row, neg_row])
    alerts = detect_ssh_bruteforce(df)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "RULE-SSH-BRUTE"
    assert alert.src_ip == "192.168.1.180"
    assert alert.mitre_technique_id == "T1110.001"
    assert alert.observed["ssh_connection_attempts"] == 18


def test_detect_arp_spoofing_positive_and_negative() -> None:
    """Verify ARP spoofing detector flags MAC binding conflicts and reply surges."""
    # Positive case 1: Multiple MACs claiming same IP
    pos_row_mac = _make_base_window(
        src_ip="192.168.1.1",
        mac_binding_changes=1,
        arp_share=0.2,
    )
    # Positive case 2: Unsolicited ARP reply flood
    pos_row_reply = _make_base_window(
        src_ip="192.168.1.199",
        arp_reply_count=12,
        arp_share=0.4,
    )
    # Negative case: Normal host with 0 MAC conflicts and 0 ARP replies
    neg_row = _make_base_window(
        src_ip="192.168.1.10",
        mac_binding_changes=0,
        arp_reply_count=0,
    )

    df = pd.DataFrame([pos_row_mac, pos_row_reply, neg_row])
    alerts = detect_arp_spoofing(df)

    assert len(alerts) == 2
    assert alerts[0].rule_id == "RULE-ARP-SPOOF"
    assert alerts[0].src_ip == "192.168.1.1"
    assert alerts[1].rule_id == "RULE-ARP-SPOOF"
    assert alerts[1].src_ip == "192.168.1.199"
    assert alerts[0].mitre_technique_id == "T1557.002"


def test_merge_adjacent_alerts() -> None:
    """Verify adjacent windows from the same attacker/rule consolidate into a single event with peak metrics."""
    # Build 3 adjacent windows for port scan: [100, 105], [105, 110], [110, 115]
    a1 = Alert(
        rule_id="RULE-PORT-SCAN",
        src_ip="192.168.1.99",
        window_start=100.0,
        window_end=105.0,
        matched_conditions=["Condition A"],
        observed={"unique_dst_ports": 30, "pps": 25.0},
        thresholds={"min_unique_ports": 20},
        strength=0.33,
        detector_name="Port Scan Detector",
    )
    a2 = Alert(
        rule_id="RULE-PORT-SCAN",
        src_ip="192.168.1.99",
        window_start=105.0,
        window_end=110.0,
        matched_conditions=["Condition B"],
        observed={"unique_dst_ports": 80, "pps": 60.0},
        thresholds={"min_unique_ports": 20},
        strength=0.75,  # peak strength
        detector_name="Port Scan Detector",
    )
    a3 = Alert(
        rule_id="RULE-PORT-SCAN",
        src_ip="192.168.1.99",
        window_start=110.0,
        window_end=115.0,
        matched_conditions=["Condition A"],
        observed={"unique_dst_ports": 45, "pps": 35.0},
        thresholds={"min_unique_ports": 20},
        strength=0.5,
        detector_name="Port Scan Detector",
    )
    # Non-adjacent alert separated by 40-second gap: [155, 160]
    a4 = Alert(
        rule_id="RULE-PORT-SCAN",
        src_ip="192.168.1.99",
        window_start=155.0,
        window_end=160.0,
        matched_conditions=["Condition C"],
        observed={"unique_dst_ports": 25, "pps": 15.0},
        thresholds={"min_unique_ports": 20},
        strength=0.25,
        detector_name="Port Scan Detector",
    )

    merged = merge_adjacent_alerts([a1, a2, a3, a4], max_window_gap=5.0)

    # Expected: 2 events (first cluster of 3 windows, second separate event of 1 window)
    assert len(merged) == 2

    # Verify event 1
    e1 = merged[0]
    assert e1.window_start == 100.0
    assert e1.window_end == 115.0
    assert e1.merged_windows_count == 3
    assert e1.strength == 0.75  # Peak strength preserved
    assert e1.observed["unique_dst_ports"] == 80  # Peak observed preserved
    assert e1.observed["pps"] == 60.0  # Peak observed preserved
    assert e1.matched_conditions == ["Condition A", "Condition B"]  # Unique union

    # Verify event 2
    e2 = merged[1]
    assert e2.window_start == 155.0
    assert e2.window_end == 160.0
    assert e2.merged_windows_count == 1


def test_detect_all_rules_pipeline() -> None:
    """Verify unified detect_all_rules runs all detectors and merges events."""
    rows = [
        # Window 1: Port scan
        _make_base_window(src_ip="192.168.1.99", win_start=100.0, win_end=105.0, unique_dst_ports=40, tcp_share=0.9, syn_without_ack_fraction=0.8),
        # Window 2: Contiguous port scan
        _make_base_window(src_ip="192.168.1.99", win_start=105.0, win_end=110.0, unique_dst_ports=50, tcp_share=0.9, syn_without_ack_fraction=0.8),
        # Window 3: Benign host
        _make_base_window(src_ip="192.168.1.10", win_start=100.0, win_end=105.0),
        # Window 4: SYN flood from different attacker
        _make_base_window(src_ip="192.168.1.150", win_start=200.0, win_end=205.0, pps=160.0, syn_count=800, synack_ratio=10.0, syn_without_ack_fraction=0.9),
    ]
    df = pd.DataFrame(rows)
    alerts = detect_all_rules(df, merge_events=True)

    # 1 merged port scan + 1 SYN flood = 2 consolidated alerts
    assert len(alerts) == 2
    rule_ids = {a.rule_id for a in alerts}
    assert "RULE-PORT-SCAN" in rule_ids
    assert "RULE-SYN-FLOOD" in rule_ids

    # Port scan should span 100 to 110 (2 windows merged)
    scan_alert = next(a for a in alerts if a.rule_id == "RULE-PORT-SCAN")
    assert scan_alert.window_start == 100.0
    assert scan_alert.window_end == 110.0
    assert scan_alert.merged_windows_count == 2


def test_threshold_tuning_sweep() -> None:
    """Verify sweep_thresholds calculates false-positive counts across threshold values."""
    benign_rows = [
        _make_base_window(src_ip="192.168.1.10", unique_dst_ports=4, pps=6.0, synack_ratio=0.5),
        _make_base_window(src_ip="192.168.1.11", unique_dst_ports=8, pps=12.0, synack_ratio=0.8),
        _make_base_window(src_ip="192.168.1.12", unique_dst_ports=2, pps=4.0, synack_ratio=0.5),
    ]
    df = pd.DataFrame(benign_rows)

    custom_sweep = {
        "port_scan": {
            "param": "min_unique_ports",
            "values": [3, 6, 10, 20],
        }
    }

    results = sweep_thresholds(df, sweep_ranges=custom_sweep)
    assert "port_scan" in results
    scan_df = results["port_scan"]

    assert len(scan_df) == 4
    # At min_unique_ports = 3: ports 4 and 8 may trigger FPs
    # At min_unique_ports = 20: 0 FPs
    fp_at_20 = scan_df[scan_df["value"] == 20]["fp_windows"].iloc[0]
    assert fp_at_20 == 0


def test_alert_to_explanation_schema() -> None:
    """Verify Alert.to_explanation converts to standard AlertExplanation contract."""
    alert = Alert(
        rule_id="RULE-PORT-SCAN",
        src_ip="192.168.1.99",
        dst_ip="192.168.1.20",
        window_start=100.0,
        window_end=110.0,
        matched_conditions=["Unique ports 50 >= 20"],
        observed={"unique_dst_ports": 50},
        thresholds={"min_unique_ports": 20},
        strength=0.6,
        detector_name="Port Scan Detector",
        severity=70,
        confidence="HIGH",
        mitre_technique_id="T1046",
        mitre_technique_name="Network Service Discovery",
        mitre_tactic="Discovery",
        merged_windows_count=2,
    )

    exp = alert.to_explanation()
    assert isinstance(exp, AlertExplanation)
    assert exp.rule_id == "RULE-PORT-SCAN"
    assert exp.source_ip == "192.168.1.99"
    assert exp.target_ip == "192.168.1.20"
    assert exp.confidence == ConfidenceLevel.HIGH
    assert exp.severity == 70
    assert exp.mitre_technique_id == "T1046"
    assert "Port Scan" in exp.summary
