"""MITRE ATT&CK Framework Mapping and Alert Schema for SentinelFlow.

Maintains enterprise MITRE ATT&CK technique IDs, names, and tactics associated with
network attack vectors (T1046, T1498.001, T1110.001, T1557.002, T1205/T1071).
Defines the core AlertExplanation data contract used throughout SentinelFlow.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ConfidenceLevel(str, Enum):
    """Enumeration of alert confidence levels."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


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


# Central MITRE ATT&CK Mapping Directory
MITRE_ATTACK_MAP: Dict[str, Dict[str, str]] = {
    "port_scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversary probes remote systems across ports to discover running services.",
    },
    "syn_flood": {
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Flood",
        "tactic": "Impact",
        "description": "Adversary overwhelms network service capacity by saturating SYN queues.",
    },
    "udp_flood": {
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Flood",
        "tactic": "Impact",
        "description": "Adversary transmits high-volume UDP datagram surges to deplete system bandwidth.",
    },
    "ssh_brute_force": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversary systematically submits candidate passwords against SSH service.",
    },
    "arp_spoofing": {
        "technique_id": "T1557.002",
        "technique_name": "Adversary-in-the-Middle: ARP Poisoning",
        "tactic": "Credential Access",
        "description": "Adversary transmits forged ARP messages to poison IP-MAC mappings.",
    },
    "unknown_anomaly": {
        "technique_id": "T1205",
        "technique_name": "Traffic Anomaly / Non-Standard Protocol Communication",
        "tactic": "Defense Evasion",
        "description": "Statistical deviation in traffic volume, timing, or protocol geometry.",
    },
}
