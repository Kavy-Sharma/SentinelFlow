"""Deterministic Rule-Based Threat Detectors for SentinelFlow.

Implements heuristic and signature-based detection rules for:
- Port Scanning (MITRE T1046: Network Service Discovery)
- SYN Flood DoS (MITRE T1498.001: Direct Network Flood)
- UDP Flood DoS (MITRE T1498.001: Direct Network Flood)
- SSH Brute Force (MITRE T1110.001: Password Guessing)
- ARP Spoofing / Poisoning (MITRE T1557.002: ARP Poisoning)

All detector thresholds are loaded from `config/default.yaml` and emit structured
`Alert` objects. Adjacent windows for the same attacker/rule are merged into unified
events with peak metrics.
"""

from dataclasses import dataclass, field
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import pandas as pd
import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path("config/default.yaml")


@dataclass
class Alert:
    """Structured intrusion alert record emitted by SentinelFlow detection rules.

    Attributes:
        rule_id: Unique rule identifier (e.g., 'RULE-PORT-SCAN').
        src_ip: Suspect source IP address.
        window_start: Beginning timestamp (epoch seconds) of the detection interval.
        window_end: Ending timestamp (epoch seconds) of the detection interval.
        matched_conditions: Human-readable explanations of conditions satisfied.
        observed: Extracted statistical metrics triggering the alert.
        thresholds: Configured rule threshold values.
        strength: Normalized severity margin in range [0.0, 1.0].
        dst_ip: Target destination IP address, if identified.
        detector_name: Human-readable detector title.
        severity: Severity score between 0 and 100.
        confidence: Confidence level ('HIGH', 'MEDIUM', 'LOW').
        mitre_technique_id: MITRE ATT&CK technique identifier.
        mitre_technique_name: MITRE ATT&CK technique name.
        mitre_tactic: MITRE ATT&CK tactic category.
        merged_windows_count: Number of consecutive time windows consolidated into this event.
    """

    rule_id: str
    src_ip: str
    window_start: float
    window_end: float
    matched_conditions: List[str]
    observed: Dict[str, Any]
    thresholds: Dict[str, Any]
    strength: float
    dst_ip: Optional[str] = None
    detector_name: str = ""
    severity: int = 70
    confidence: str = "HIGH"
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    mitre_tactic: str = ""
    merged_windows_count: int = 1

    def to_explanation(self) -> Any:
        """Convert Alert into standardized AlertExplanation dataclass."""
        from sentinelflow.attack_map import AlertExplanation, ConfidenceLevel

        conf_enum = ConfidenceLevel.HIGH
        if str(self.confidence).upper() == "MEDIUM":
            conf_enum = ConfidenceLevel.MEDIUM
        elif str(self.confidence).upper() == "LOW":
            conf_enum = ConfidenceLevel.LOW

        summary = (
            f"Detected {self.detector_name or self.rule_id} from {self.src_ip} "
            f"spanning {self.window_end - self.window_start:.1f}s ({self.merged_windows_count} windows)"
        )
        return AlertExplanation(
            rule_id=self.rule_id,
            detector_name=self.detector_name or self.rule_id,
            matched_conditions=self.matched_conditions,
            observed_values=self.observed,
            thresholds=self.thresholds,
            anomaly_score=self.strength,
            top_deviating_features={},
            severity=self.severity,
            confidence=conf_enum,
            mitre_technique_id=self.mitre_technique_id,
            mitre_technique_name=self.mitre_technique_name,
            mitre_tactic=self.mitre_tactic,
            source_ip=self.src_ip,
            target_ip=self.dst_ip,
            timestamp=self.window_start,
            summary=summary,
        )


def load_rules_config(config_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Load detector thresholds from configuration YAML file.

    Args:
        config_path: Optional path to YAML config file. If None, checks default.yaml.

    Returns:
        Dictionary of rule thresholds.
    """
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    if not path.is_file():
        logger.warning("Config file '%s' not found; using fallback default thresholds.", path)
        return _get_fallback_rules_config()

    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        return cfg.get("rules", _get_fallback_rules_config())
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed loading config from '%s': %s; using defaults.", path, exc)
        return _get_fallback_rules_config()


def _get_fallback_rules_config() -> Dict[str, Any]:
    """Provide hard-coded fallback thresholds if config file is unavailable."""
    return {
        "port_scan": {
            "enabled": True,
            "min_unique_ports": 20,
            "min_syn_ratio": 0.8,
            "severity": 70,
            "confidence": "HIGH",
        },
        "syn_flood": {
            "enabled": True,
            "syn_packet_rate_per_sec": 100.0,
            "syn_ack_ratio_threshold": 4.0,
            "severity": 85,
            "confidence": "HIGH",
        },
        "udp_flood": {
            "enabled": True,
            "udp_packet_rate_per_sec": 150.0,
            "min_packet_count": 500,
            "severity": 80,
            "confidence": "HIGH",
        },
        "ssh_brute_force": {
            "enabled": True,
            "target_port": 22,
            "attempts_per_window": 10,
            "max_payload_bytes": 4096,
            "severity": 75,
            "confidence": "MEDIUM",
        },
        "arp_spoof": {
            "enabled": True,
            "max_macs_per_ip": 1,
            "unsolicited_reply_threshold": 5,
            "severity": 90,
            "confidence": "HIGH",
        },
    }


def _calc_normalized_strength(observed_val: float, threshold_val: float, scale_factor: float = 2.0) -> float:
    """Calculate normalized margin over threshold in range [0.0, 1.0]."""
    if threshold_val <= 0:
        return 1.0 if observed_val > 0 else 0.0
    if observed_val <= threshold_val:
        return 0.0
    margin = (observed_val - threshold_val) / (threshold_val * scale_factor)
    return float(min(1.0, max(0.05, margin)))


def detect_port_scan(
    windows_df: pd.DataFrame,
    config: Optional[Dict[str, Any]] = None,
    packets_df: Optional[pd.DataFrame] = None,
) -> List[Alert]:
    """Detect horizontal or vertical port scanning activity (MITRE T1046).

    Detection Strategy:
    Scanners iterate through destination ports on target systems in rapid succession.
    Triggers when unique destination port diversity exceeds `min_unique_ports` and
    traffic is predominantly TCP SYN probes or unacknowledged handshakes.
    """
    if windows_df.empty:
        return []

    cfg = (config or {}).get("port_scan", _get_fallback_rules_config()["port_scan"])
    if not cfg.get("enabled", True):
        return []

    min_ports = int(cfg.get("min_unique_ports", 20))
    min_syn_ratio = float(cfg.get("min_syn_ratio", 0.8))
    severity = int(cfg.get("severity", 70))
    confidence = str(cfg.get("confidence", "HIGH"))

    alerts: List[Alert] = []

    for _, row in windows_df.iterrows():
        ports = int(row.get("unique_dst_ports", 0))
        syn_without_ack = float(row.get("syn_without_ack_fraction", 0.0))
        tcp_share = float(row.get("tcp_share", 0.0))
        src_ip = str(row.get("src_ip", ""))
        w_start = float(row.get("win_start", 0.0))
        w_end = float(row.get("win_end", 0.0))

        # Check conditions
        matched_conds: List[str] = []
        if ports >= min_ports:
            matched_conds.append(f"Destination port diversity ({ports}) >= threshold ({min_ports})")

        # Port scans exhibit either high unacknowledged SYN fraction or pure TCP dominance
        if ports >= min_ports and (syn_without_ack >= 0.4 or tcp_share >= min_syn_ratio):
            matched_conds.append(
                f"Elevated SYN ratio / unacknowledged handshakes ({syn_without_ack:.1%}) indicates scan probes"
            )

            # Strength is proportional to port diversity over threshold
            strength = _calc_normalized_strength(ports, min_ports, scale_factor=3.0)

            # Attempt finding primary target dst_ip if packets_df is supplied
            dst_ip: Optional[str] = None
            if packets_df is not None and not packets_df.empty:
                mask = (
                    (packets_df["src_ip"] == src_ip)
                    & (packets_df["ts"] >= w_start)
                    & (packets_df["ts"] < w_end)
                    & packets_df["dst_ip"].notna()
                )
                sub_pkts = packets_df[mask]
                if not sub_pkts.empty:
                    dst_ip = str(sub_pkts["dst_ip"].mode()[0])

            alerts.append(
                Alert(
                    rule_id="RULE-PORT-SCAN",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    window_start=w_start,
                    window_end=w_end,
                    matched_conditions=matched_conds,
                    observed={
                        "unique_dst_ports": ports,
                        "syn_without_ack_fraction": syn_without_ack,
                        "tcp_share": tcp_share,
                        "pps": float(row.get("pps", 0.0)),
                    },
                    thresholds={
                        "min_unique_ports": min_ports,
                        "min_syn_ratio": min_syn_ratio,
                    },
                    strength=strength,
                    detector_name="Port Scan Detector",
                    severity=severity,
                    confidence=confidence,
                    mitre_technique_id="T1046",
                    mitre_technique_name="Network Service Discovery",
                    mitre_tactic="Discovery",
                )
            )

    return alerts


def detect_syn_flood(
    windows_df: pd.DataFrame,
    config: Optional[Dict[str, Any]] = None,
    packets_df: Optional[pd.DataFrame] = None,
) -> List[Alert]:
    """Detect TCP SYN flood volumetric DoS attacks (MITRE T1498.001).

    Detection Strategy:
    SYN floods generate massive packet surges with randomized source ports or spoofed
    IPs while never completing handshakes. Triggers when SYN rate and SYN/ACK ratio
    exceed thresholds.
    """
    if windows_df.empty:
        return []

    cfg = (config or {}).get("syn_flood", _get_fallback_rules_config()["syn_flood"])
    if not cfg.get("enabled", True):
        return []

    rate_thresh = float(cfg.get("syn_packet_rate_per_sec", 100.0))
    ratio_thresh = float(cfg.get("syn_ack_ratio_threshold", 4.0))
    severity = int(cfg.get("severity", 85))
    confidence = str(cfg.get("confidence", "HIGH"))

    alerts: List[Alert] = []

    for _, row in windows_df.iterrows():
        pps = float(row.get("pps", 0.0))
        tcp_share = float(row.get("tcp_share", 0.0))
        syn_count = int(row.get("syn_count", 0))
        synack_ratio = float(row.get("synack_ratio", 0.0))
        syn_without_ack = float(row.get("syn_without_ack_fraction", 0.0))
        w_start = float(row.get("win_start", 0.0))
        w_end = float(row.get("win_end", 0.0))
        duration = max(1e-3, w_end - w_start)
        syn_rate = syn_count / duration if syn_count > 0 else pps * tcp_share

        # Conditions
        cond_rate = (syn_rate >= rate_thresh) or (pps >= rate_thresh and tcp_share >= 0.7)
        cond_ratio = (synack_ratio >= ratio_thresh) or (syn_without_ack >= 0.75)

        if cond_rate and cond_ratio:
            matched_conds = [
                f"SYN packet transmission rate ({syn_rate:.1f} pps) >= threshold ({rate_thresh:.1f})",
                f"SYN/ACK response imbalance ratio ({synack_ratio:.1f}) >= threshold ({ratio_thresh:.1f})",
            ]
            if syn_without_ack >= 0.75:
                matched_conds.append(f"Unacknowledged SYN fraction ({syn_without_ack:.1%}) indicates flood backlog")

            strength = max(
                _calc_normalized_strength(syn_rate, rate_thresh, scale_factor=2.0),
                _calc_normalized_strength(synack_ratio, ratio_thresh, scale_factor=5.0),
            )

            src_ip = str(row.get("src_ip", ""))
            dst_ip: Optional[str] = None
            if packets_df is not None and not packets_df.empty:
                mask = (
                    (packets_df["src_ip"] == src_ip)
                    & (packets_df["ts"] >= w_start)
                    & (packets_df["ts"] < w_end)
                    & packets_df["dst_ip"].notna()
                )
                sub_pkts = packets_df[mask]
                if not sub_pkts.empty:
                    dst_ip = str(sub_pkts["dst_ip"].mode()[0])

            alerts.append(
                Alert(
                    rule_id="RULE-SYN-FLOOD",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    window_start=w_start,
                    window_end=w_end,
                    matched_conditions=matched_conds,
                    observed={
                        "syn_rate_pps": syn_rate,
                        "pps": pps,
                        "synack_ratio": synack_ratio,
                        "syn_without_ack_fraction": syn_without_ack,
                        "tcp_share": tcp_share,
                    },
                    thresholds={
                        "syn_packet_rate_per_sec": rate_thresh,
                        "syn_ack_ratio_threshold": ratio_thresh,
                    },
                    strength=strength,
                    detector_name="SYN Flood DoS Detector",
                    severity=severity,
                    confidence=confidence,
                    mitre_technique_id="T1498.001",
                    mitre_technique_name="Direct Network Flood",
                    mitre_tactic="Impact",
                )
            )

    return alerts


def detect_udp_flood(
    windows_df: pd.DataFrame,
    config: Optional[Dict[str, Any]] = None,
    packets_df: Optional[pd.DataFrame] = None,
) -> List[Alert]:
    """Detect volumetric UDP flood DoS attacks (MITRE T1498.001).

    Detection Strategy:
    Surges of high-rate UDP datagrams targeting arbitrary or closed unestablished ports.
    Triggers when UDP packet rate and UDP traffic share dominate the window.
    """
    if windows_df.empty:
        return []

    cfg = (config or {}).get("udp_flood", _get_fallback_rules_config()["udp_flood"])
    if not cfg.get("enabled", True):
        return []

    rate_thresh = float(cfg.get("udp_packet_rate_per_sec", 150.0))
    min_packets = int(cfg.get("min_packet_count", 500))
    severity = int(cfg.get("severity", 80))
    confidence = str(cfg.get("confidence", "HIGH"))

    alerts: List[Alert] = []

    for _, row in windows_df.iterrows():
        pps = float(row.get("pps", 0.0))
        udp_share = float(row.get("udp_share", 0.0))
        udp_rate = pps * udp_share
        packet_count = int(row.get("packet_count", 0))
        w_start = float(row.get("win_start", 0.0))
        w_end = float(row.get("win_end", 0.0))

        # Check conditions: high UDP rate or high packet volume dominated by UDP
        is_rate_surge = udp_rate >= rate_thresh or (pps >= 100.0 and udp_share >= 0.8)
        is_volumetric = packet_count >= min_packets and udp_share >= 0.7

        if (is_rate_surge or is_volumetric) and udp_share >= 0.65:
            matched_conds = [
                f"UDP packet rate ({udp_rate:.1f} pps) exceeds flood threshold ({rate_thresh:.1f})",
                f"UDP protocol traffic share ({udp_share:.1%}) dominates host transmission",
            ]
            strength = _calc_normalized_strength(udp_rate, rate_thresh, scale_factor=2.0)

            src_ip = str(row.get("src_ip", ""))
            dst_ip: Optional[str] = None
            if packets_df is not None and not packets_df.empty:
                mask = (
                    (packets_df["src_ip"] == src_ip)
                    & (packets_df["ts"] >= w_start)
                    & (packets_df["ts"] < w_end)
                    & packets_df["dst_ip"].notna()
                )
                sub_pkts = packets_df[mask]
                if not sub_pkts.empty:
                    dst_ip = str(sub_pkts["dst_ip"].mode()[0])

            alerts.append(
                Alert(
                    rule_id="RULE-UDP-FLOOD",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    window_start=w_start,
                    window_end=w_end,
                    matched_conditions=matched_conds,
                    observed={
                        "udp_rate_pps": udp_rate,
                        "pps": pps,
                        "packet_count": packet_count,
                        "udp_share": udp_share,
                        "bps": float(row.get("bps", 0.0)),
                    },
                    thresholds={
                        "udp_packet_rate_per_sec": rate_thresh,
                        "min_packet_count": min_packets,
                    },
                    strength=strength,
                    detector_name="UDP Flood DoS Detector",
                    severity=severity,
                    confidence=confidence,
                    mitre_technique_id="T1498.001",
                    mitre_technique_name="Direct Network Flood",
                    mitre_tactic="Impact",
                )
            )

    return alerts


def detect_ssh_bruteforce(
    windows_df: pd.DataFrame,
    config: Optional[Dict[str, Any]] = None,
    packets_df: Optional[pd.DataFrame] = None,
) -> List[Alert]:
    """Detect repeated SSH authentication guessing attacks (MITRE T1110.001).

    Detection Strategy:
    High frequency of distinct, short TCP sessions focused on port 22 with small
    cryptographic payloads and failed handshakes/resets.
    """
    if windows_df.empty:
        return []

    cfg = (config or {}).get("ssh_brute_force", _get_fallback_rules_config()["ssh_brute_force"])
    if not cfg.get("enabled", True):
        return []

    target_port = int(cfg.get("target_port", 22))
    attempts_thresh = int(cfg.get("attempts_per_window", 10))
    max_payload = float(cfg.get("max_payload_bytes", 4096))
    severity = int(cfg.get("severity", 75))
    confidence = str(cfg.get("confidence", "MEDIUM"))

    alerts: List[Alert] = []

    for _, row in windows_df.iterrows():
        src_ip = str(row.get("src_ip", ""))
        w_start = float(row.get("win_start", 0.0))
        w_end = float(row.get("win_end", 0.0))
        duration = max(1e-3, w_end - w_start)
        short_fraction = float(row.get("short_connection_fraction", 0.0))
        mean_pkt_size = float(row.get("mean_packet_size", 0.0))
        conn_max = int(row.get("connections_to_same_dst_port_max", 0))

        # Check via packet inspection if packets_df is available, otherwise feature estimation
        ssh_attempts = 0
        target_ip: Optional[str] = None

        if packets_df is not None and not packets_df.empty:
            mask = (
                (packets_df["src_ip"] == src_ip)
                & (packets_df["ts"] >= w_start)
                & (packets_df["ts"] < w_end)
                & (packets_df["proto"] == "TCP")
                & (packets_df["dst_port"] == target_port)
            )
            ssh_pkts = packets_df[mask]
            if not ssh_pkts.empty:
                # Count distinct source ports attempting port 22
                ssh_attempts = int(ssh_pkts["src_port"].nunique())
                target_ip = str(ssh_pkts["dst_ip"].mode()[0])
        else:
            # Feature fallback: connections_to_same_dst_port_max
            ssh_attempts = conn_max

        # Trigger condition: high concentrated connection attempts with short lifecycle
        thresh = max(3, int(attempts_thresh * (duration / 30.0))) if duration < 25.0 else attempts_thresh
        if (ssh_attempts >= thresh or conn_max >= attempts_thresh) and (short_fraction >= 0.4 or mean_pkt_size <= 600.0):
            matched_conds = [
                f"Repeated connection attempts ({ssh_attempts}) targeting port {target_port} >= threshold ({thresh})",
                f"Short/aborted session fraction ({short_fraction:.1%}) characteristic of authentication failure loops",
            ]
            strength = _calc_normalized_strength(ssh_attempts, thresh, scale_factor=3.0)

            alerts.append(
                Alert(
                    rule_id="RULE-SSH-BRUTE",
                    src_ip=src_ip,
                    dst_ip=target_ip,
                    window_start=w_start,
                    window_end=w_end,
                    matched_conditions=matched_conds,
                    observed={
                        "ssh_connection_attempts": ssh_attempts,
                        "short_connection_fraction": short_fraction,
                        "mean_packet_size": mean_pkt_size,
                        "connections_to_same_dst_port_max": conn_max,
                    },
                    thresholds={
                        "target_port": target_port,
                        "attempts_per_window": attempts_thresh,
                        "max_payload_bytes": max_payload,
                    },
                    strength=strength,
                    detector_name="SSH Brute Force Detector",
                    severity=severity,
                    confidence=confidence,
                    mitre_technique_id="T1110.001",
                    mitre_technique_name="Brute Force: Password Guessing",
                    mitre_tactic="Credential Access",
                )
            )

    return alerts


def detect_arp_spoofing(
    windows_df: pd.DataFrame,
    config: Optional[Dict[str, Any]] = None,
    packets_df: Optional[pd.DataFrame] = None,
) -> List[Alert]:
    """Detect ARP cache poisoning and Man-in-the-Middle attacks (MITRE T1557.002).

    Detection Strategy:
    Monitors for multiple MAC addresses claiming the same IP in inspection tables
    or an unsolicited flood of gratuitous ARP replies (op=2).
    """
    if windows_df.empty:
        return []

    cfg = (config or {}).get("arp_spoof", _get_fallback_rules_config()["arp_spoof"])
    if not cfg.get("enabled", True):
        return []

    max_macs = int(cfg.get("max_macs_per_ip", 1))
    reply_thresh = int(cfg.get("unsolicited_reply_threshold", 5))
    severity = int(cfg.get("severity", 90))
    confidence = str(cfg.get("confidence", "HIGH"))

    alerts: List[Alert] = []

    for _, row in windows_df.iterrows():
        mac_changes = int(row.get("mac_binding_changes", 0))
        arp_replies = int(row.get("arp_reply_count", 0))
        arp_share = float(row.get("arp_share", 0.0))
        src_ip = str(row.get("src_ip", ""))
        w_start = float(row.get("win_start", 0.0))
        w_end = float(row.get("win_end", 0.0))
        duration = max(1e-3, w_end - w_start)

        # Check conditions: ARP spoofing requires ARP protocol activity
        has_arp_activity = (arp_replies > 0) or (arp_share > 0.0)
        thresh_replies = max(2, int(reply_thresh * (duration / 10.0))) if duration < 10.0 else reply_thresh

        cond_mac = (mac_changes >= max_macs) and has_arp_activity
        cond_reply = (arp_replies >= thresh_replies) and (arp_share >= 0.1 or arp_replies >= 3)

        # If packets_df is provided, inspect historical MAC bindings for this IP
        if packets_df is not None and not packets_df.empty:
            ip_macs = packets_df[packets_df["src_ip"] == src_ip]["src_mac"].dropna().unique()
            if len(ip_macs) > max_macs and has_arp_activity:
                cond_mac = True
                mac_changes = max(mac_changes, len(ip_macs) - 1)

        if cond_mac or cond_reply:
            matched_conds: List[str] = []
            if cond_mac:
                matched_conds.append(
                    f"MAC binding divergence ({mac_changes} conflicting MACs observed claiming IP {src_ip})"
                )
            if cond_reply:
                matched_conds.append(
                    f"Unsolicited ARP reply flood ({arp_replies} replies) >= threshold ({thresh_replies})"
                )

            # Strength: higher if conflicting MACs or heavy reply flood
            strength_mac = 1.0 if cond_mac else 0.0
            strength_reply = _calc_normalized_strength(arp_replies, thresh_replies, scale_factor=3.0)
            strength = max(strength_mac, strength_reply)

            # Attempt finding target destination IP
            dst_ip: Optional[str] = None
            if packets_df is not None and not packets_df.empty:
                mask = (
                    (packets_df["src_ip"] == src_ip)
                    & (packets_df["ts"] >= w_start)
                    & (packets_df["ts"] < w_end)
                    & (packets_df["proto"] == "ARP")
                    & packets_df["dst_ip"].notna()
                )
                sub_pkts = packets_df[mask]
                if not sub_pkts.empty:
                    dst_ip = str(sub_pkts["dst_ip"].mode()[0])

            alerts.append(
                Alert(
                    rule_id="RULE-ARP-SPOOF",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    window_start=w_start,
                    window_end=w_end,
                    matched_conditions=matched_conds,
                    observed={
                        "mac_binding_changes": mac_changes,
                        "arp_reply_count": arp_replies,
                        "arp_share": arp_share,
                    },
                    thresholds={
                        "max_macs_per_ip": max_macs,
                        "unsolicited_reply_threshold": reply_thresh,
                    },
                    strength=strength,
                    detector_name="ARP Spoofing / Poisoning Detector",
                    severity=severity,
                    confidence=confidence,
                    mitre_technique_id="T1557.002",
                    mitre_technique_name="Adversary-in-the-Middle: ARP Poisoning",
                    mitre_tactic="Credential Access",
                )
            )

    return alerts


def merge_adjacent_alerts(alerts: List[Alert], max_window_gap: float = 5.0) -> List[Alert]:
    """Merge adjacent or overlapping time-window alerts from the same source and rule into a single event.

    Ensures security analysts inspect a consolidated incident event with overall start/end
    and peak metric values, rather than redundant window-by-window rows.

    Args:
        alerts: List of individual Alert instances.
        max_window_gap: Maximum gap in seconds between consecutive windows to be considered part
                        of the same attack incident (default: 5.0s).

    Returns:
        List of consolidated Alert events.
    """
    if not alerts:
        return []

    # Group alerts by (rule_id, src_ip, dst_ip)
    grouped: Dict[Tuple[str, str, Optional[str]], List[Alert]] = {}
    for a in alerts:
        key = (a.rule_id, a.src_ip, a.dst_ip)
        grouped.setdefault(key, []).append(a)

    merged_results: List[Alert] = []

    for _, group in grouped.items():
        # Sort chronologically by window_start
        sorted_alerts = sorted(group, key=lambda x: x.window_start)

        current_cluster: List[Alert] = [sorted_alerts[0]]

        for next_alert in sorted_alerts[1:]:
            last_alert = current_cluster[-1]
            # Check adjacency: next_alert starts before or within max_window_gap of previous window_end
            if next_alert.window_start <= last_alert.window_end + max_window_gap:
                current_cluster.append(next_alert)
            else:
                # Close out current cluster and start new one
                merged_results.append(_consolidate_alert_cluster(current_cluster))
                current_cluster = [next_alert]

        if current_cluster:
            merged_results.append(_consolidate_alert_cluster(current_cluster))

    # Return sorted by incident start time
    merged_results.sort(key=lambda x: (x.window_start, x.src_ip))
    return merged_results


def _consolidate_alert_cluster(cluster: List[Alert]) -> Alert:
    """Consolidate a cluster of adjacent window alerts into a single incident event."""
    if len(cluster) == 1:
        return cluster[0]

    base = cluster[0]
    win_start = min(a.window_start for a in cluster)
    win_end = max(a.window_end for a in cluster)
    peak_strength = max(a.strength for a in cluster)

    # Union unique matched conditions preserving order
    all_conds: List[str] = []
    seen_conds = set()
    for a in cluster:
        for c in a.matched_conditions:
            if c not in seen_conds:
                seen_conds.add(c)
                all_conds.append(c)

    # Aggregate observed metrics: record peak values across all windows
    peak_observed: Dict[str, Any] = {}
    for a in cluster:
        for k, v in a.observed.items():
            if isinstance(v, (int, float)):
                peak_observed[k] = max(peak_observed.get(k, v), v)
            else:
                peak_observed[k] = v

    # Peak severity and highest confidence
    peak_severity = max(a.severity for a in cluster)
    confidence_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    best_conf = max((a.confidence for a in cluster), key=lambda c: confidence_rank.get(c, 0))

    return Alert(
        rule_id=base.rule_id,
        src_ip=base.src_ip,
        dst_ip=base.dst_ip,
        window_start=win_start,
        window_end=win_end,
        matched_conditions=all_conds,
        observed=peak_observed,
        thresholds=base.thresholds,
        strength=peak_strength,
        detector_name=base.detector_name,
        severity=peak_severity,
        confidence=best_conf,
        mitre_technique_id=base.mitre_technique_id,
        mitre_technique_name=base.mitre_technique_name,
        mitre_tactic=base.mitre_tactic,
        merged_windows_count=len(cluster),
    )


def detect_all_rules(
    windows_df: pd.DataFrame,
    packets_df: Optional[pd.DataFrame] = None,
    config: Optional[Dict[str, Any]] = None,
    merge_events: bool = True,
) -> List[Alert]:
    """Execute all rule-based detectors and optionally merge adjacent window alerts.

    Args:
        windows_df: Extracted features DataFrame from sentinelflow.features.
        packets_df: Optional raw parsed packet DataFrame for fine-grained inspection.
        config: Optional dictionary of detector thresholds (loads default.yaml if None).
        merge_events: If True, consolidates adjacent window alerts into single events.

    Returns:
        List of Alert objects representing detected threats.
    """
    if windows_df.empty:
        return []

    cfg = config if config is not None else load_rules_config()

    raw_alerts: List[Alert] = []
    raw_alerts.extend(detect_port_scan(windows_df, cfg, packets_df))
    raw_alerts.extend(detect_syn_flood(windows_df, cfg, packets_df))
    raw_alerts.extend(detect_udp_flood(windows_df, cfg, packets_df))
    raw_alerts.extend(detect_ssh_bruteforce(windows_df, cfg, packets_df))
    raw_alerts.extend(detect_arp_spoofing(windows_df, cfg, packets_df))

    if merge_events:
        return merge_adjacent_alerts(raw_alerts)
    return raw_alerts
