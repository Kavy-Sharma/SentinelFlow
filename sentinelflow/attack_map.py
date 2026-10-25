"""MITRE ATT&CK Framework Mapping and Alert Schema for SentinelFlow.

Maintains enterprise MITRE ATT&CK technique IDs, names, tactics, and actionable analyst
recommendations associated with network attack vectors:
- Port Scanning (T1046: Network Service Discovery)
- SYN / UDP Floods (T1498: Network Denial of Service)
- SSH Brute Force (T1110: Brute Force)
- ARP Spoofing / Poisoning (T1557.002: ARP Cache Poisoning)
- Unsupervised Traffic Anomalies (T1205: Traffic Anomaly / Non-Standard Protocol Communication)

Defines the core AlertExplanation data contract used throughout SentinelFlow.
"""

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Union


class ConfidenceLevel(str, Enum):
    """Enumeration of alert confidence levels."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Central MITRE ATT&CK Mapping Directory with one-line analyst recommendations
MITRE_ATTACK_MAP: Dict[str, Dict[str, str]] = {
    "port_scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversary probes remote systems across ports to discover running services.",
        "recommendation": "Block suspect source IP at border firewall, audit exposed ports on target host, and enforce subnet isolation.",
    },
    "syn_flood": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversary overwhelms network service capacity by saturating TCP SYN backlog queues.",
        "recommendation": "Enable SYN cookies on target hosts, apply ingress rate limiting at perimeter router, and activate upstream DDoS scrubbing.",
    },
    "udp_flood": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversary transmits high-volume UDP datagram surges to saturate link bandwidth and host resources.",
        "recommendation": "Deploy stateless UDP rate limiting at border gateway, drop unestablished UDP traffic, and verify upstream DDoS mitigation.",
    },
    "ssh_bruteforce": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversary systematically submits candidate passwords against SSH service.",
        "recommendation": "Quarantine source IP, enforce fail2ban/connection rate-limiting on port 22, and mandate ed25519 public-key authentication.",
    },
    "arp_spoofing": {
        "technique_id": "T1557.002",
        "technique_name": "ARP Cache Poisoning",
        "tactic": "Credential Access",
        "description": "Adversary transmits forged ARP messages to poison IP-to-MAC hardware bindings.",
        "recommendation": "Isolate suspect switch port, inspect physical CAM table, and enforce Dynamic ARP Inspection (DAI) with DHCP Snooping.",
    },
    "unknown_anomaly": {
        "technique_id": "T1205",
        "technique_name": "Traffic Anomaly / Non-Standard Protocol Communication",
        "tactic": "Defense Evasion",
        "description": "Statistical deviation in traffic volume, timing, or protocol geometry flagged by Isolation Forest.",
        "recommendation": "Quarantine affected host for endpoint forensics, inspect packet payloads for C2 beaconing, and verify baseline asset behavior.",
    },
}

# Rule identifier normalization aliases
RULE_ALIAS_MAP: Dict[str, str] = {
    "rule-port-scan": "port_scan",
    "port_scan": "port_scan",
    "port-scan": "port_scan",
    "rule-syn-flood": "syn_flood",
    "syn_flood": "syn_flood",
    "syn-flood": "syn_flood",
    "rule-udp-flood": "udp_flood",
    "udp_flood": "udp_flood",
    "udp-flood": "udp_flood",
    "rule-ssh-brute": "ssh_bruteforce",
    "rule-ssh-bruteforce": "ssh_bruteforce",
    "ssh_bruteforce": "ssh_bruteforce",
    "ssh_brute_force": "ssh_bruteforce",
    "ssh-brute-force": "ssh_bruteforce",
    "rule-arp-spoof": "arp_spoofing",
    "rule-arp-spoofing": "arp_spoofing",
    "arp_spoofing": "arp_spoofing",
    "arp_spoof": "arp_spoofing",
    "arp-spoof": "arp_spoofing",
    "ml-iforest-anomaly": "unknown_anomaly",
    "unknown_anomaly": "unknown_anomaly",
    "unknown-anomaly": "unknown_anomaly",
    "anomaly": "unknown_anomaly",
}


def normalize_rule_key(key: str) -> str:
    """Normalize rule ID or attack vector string into standard canonical key."""
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "_", key.strip().lower())
    cleaned_hyphen = re.sub(r"[^a-zA-Z0-9]+", "-", key.strip().lower())

    if key.lower() in RULE_ALIAS_MAP:
        return RULE_ALIAS_MAP[key.lower()]
    if cleaned in RULE_ALIAS_MAP:
        return RULE_ALIAS_MAP[cleaned]
    if cleaned_hyphen in RULE_ALIAS_MAP:
        return RULE_ALIAS_MAP[cleaned_hyphen]

    for k, canonical in RULE_ALIAS_MAP.items():
        if k in key.lower():
            return canonical

    return "unknown_anomaly"


def get_mitre_info(rule_id_or_attack: str) -> Dict[str, str]:
    """Retrieve MITRE ATT&CK technique details for a rule or attack identifier.

    Args:
        rule_id_or_attack: Rule ID (e.g., 'RULE-PORT-SCAN') or attack name ('port_scan').

    Returns:
        Dictionary with keys: technique_id, technique_name, tactic, description, recommendation.
    """
    canonical = normalize_rule_key(rule_id_or_attack)
    return MITRE_ATTACK_MAP.get(canonical, MITRE_ATTACK_MAP["unknown_anomaly"])


def get_recommendation(rule_id_or_attack: str) -> str:
    """Retrieve the one-line analyst recommendation for a detected threat."""
    return get_mitre_info(rule_id_or_attack).get("recommendation", "")


def generate_plain_english_explanation(
    detector_name: str,
    technique_id: str,
    severity: int,
    confidence: Union[ConfidenceLevel, str],
    source_ip: Optional[str] = None,
    target_ip: Optional[str] = None,
    duration: float = 0.0,
    merged_windows_count: int = 1,
    matched_conditions: Optional[List[str]] = None,
    observed_values: Optional[Dict[str, Any]] = None,
    thresholds: Optional[Dict[str, Any]] = None,
    top_deviating_features: Optional[Dict[str, float]] = None,
    recommendation: str = "",
) -> str:
    """Generate a single cohesive plain-English explanation string for an alert.

    Includes observed values vs expected thresholds, top deviating features,
    MITRE technique ID, severity, confidence, and actionable recommendation.
    """
    conf_str = confidence.value if isinstance(confidence, ConfidenceLevel) else str(confidence)
    target_str = f" -> {target_ip}" if target_ip else ""
    dur_str = f" spanning {duration:.1f}s ({merged_windows_count} window{'s' if merged_windows_count != 1 else ''})" if duration > 0 else ""

    parts = [
        f"Detected {detector_name} [{technique_id}] (Severity: {severity}/100, Confidence: {conf_str}) "
        f"from {source_ip or 'unknown'}{target_str}{dur_str}."
    ]

    # Matched conditions
    if matched_conditions:
        clean_conds = "; ".join(c.strip().rstrip(".") for c in matched_conditions)
        parts.append(f"Conditions: {clean_conds}.")

    # Observed vs Thresholds
    obs_parts: List[str] = []
    obs = observed_values or {}
    thresh = thresholds or {}

    for k, v in obs.items():
        if k in thresh:
            th_v = thresh[k]
            if isinstance(v, float):
                obs_parts.append(f"{k}={v:.1f} (thresh: {th_v})")
            else:
                obs_parts.append(f"{k}={v} (thresh: {th_v})")
        else:
            if isinstance(v, float):
                obs_parts.append(f"{k}={v:.1f}")
            elif isinstance(v, (int, str)):
                obs_parts.append(f"{k}={v}")

    if obs_parts:
        parts.append(f"Observed: {', '.join(obs_parts[:6])}.")

    # Top deviating features
    if top_deviating_features:
        feat_strs = []
        for feat, z in list(top_deviating_features.items())[:3]:
            sign = f"+{z:.1f}σ" if z >= 0 else f"{z:.1f}σ"
            feat_strs.append(f"{feat} {sign}")
        parts.append(f"Baseline deviations: {', '.join(feat_strs)}.")

    # Analyst Recommendation
    if recommendation:
        parts.append(f"Recommendation: {recommendation.strip().rstrip('.')}.")

    return " ".join(parts)


@dataclass
class AlertExplanation:
    """Standardized explainable alert record contract (AGENTS.md Section 6).

    Attributes:
        rule_id: Rule or ML detector identifier (e.g., 'RULE-PORT-SCAN').
        detector_name: Human-readable detector title.
        matched_conditions: Boolean/threshold conditions satisfied.
        observed_values: Extracted metrics observed during the window/incident.
        thresholds: Expected baseline thresholds.
        anomaly_score: Normalized anomaly score (0.0 to 1.0).
        top_deviating_features: Top features ranked by z-score deviation.
        severity: Severity score between 0 and 100.
        confidence: Confidence level (HIGH, MEDIUM, LOW).
        mitre_technique_id: MITRE technique ID (e.g., 'T1046').
        mitre_technique_name: MITRE technique name.
        mitre_tactic: MITRE tactic category.
        source_ip: Source IP address.
        target_ip: Target destination IP address if applicable.
        timestamp: Incident epoch timestamp.
        summary: Human-readable incident summary.
        recommendation: One-line actionable analyst recommendation.
        window_end: Incident ending epoch timestamp.
        duration: Incident duration in seconds.
        merged_windows_count: Number of consolidated time windows.
    """

    rule_id: str
    detector_name: str
    matched_conditions: List[str]
    observed_values: Dict[str, Any]
    thresholds: Dict[str, Any]
    anomaly_score: float = 0.0
    top_deviating_features: Dict[str, float] = field(default_factory=dict)
    severity: int = 70
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    mitre_tactic: str = ""
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    timestamp: Optional[float] = None
    summary: str = ""
    recommendation: str = ""
    window_end: Optional[float] = None
    duration: float = 0.0
    merged_windows_count: int = 1

    def __post_init__(self) -> None:
        """Populate MITRE details, recommendation, and plain-English summary if omitted."""
        if not self.mitre_technique_id or not self.mitre_technique_name or not self.recommendation:
            info = get_mitre_info(self.rule_id)
            if not self.mitre_technique_id:
                self.mitre_technique_id = info["technique_id"]
            if not self.mitre_technique_name:
                self.mitre_technique_name = info["technique_name"]
            if not self.mitre_tactic:
                self.mitre_tactic = info["tactic"]
            if not self.recommendation:
                self.recommendation = info["recommendation"]

        if self.timestamp is not None and self.window_end is not None and self.duration == 0.0:
            self.duration = max(0.0, self.window_end - self.timestamp)

        if not self.summary:
            self.summary = generate_plain_english_explanation(
                detector_name=self.detector_name,
                technique_id=self.mitre_technique_id,
                severity=self.severity,
                confidence=self.confidence,
                source_ip=self.source_ip,
                target_ip=self.target_ip,
                duration=self.duration,
                merged_windows_count=self.merged_windows_count,
                matched_conditions=self.matched_conditions,
                observed_values=self.observed_values,
                thresholds=self.thresholds,
                top_deviating_features=self.top_deviating_features,
                recommendation=self.recommendation,
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert record into JSON-serializable dictionary."""
        return {
            "rule_id": self.rule_id,
            "detector_name": self.detector_name,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "window_start": self.timestamp,
            "window_end": self.window_end,
            "duration": round(self.duration, 2),
            "merged_windows_count": self.merged_windows_count,
            "severity": self.severity,
            "confidence": self.confidence.value if isinstance(self.confidence, ConfidenceLevel) else str(self.confidence),
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "mitre_tactic": self.mitre_tactic,
            "anomaly_score": round(self.anomaly_score, 4),
            "matched_conditions": self.matched_conditions,
            "observed_values": self.observed_values,
            "thresholds": self.thresholds,
            "top_deviating_features": self.top_deviating_features,
            "recommendation": self.recommendation,
            "summary": self.summary,
        }
