"""Data models and configuration schemas for synthetic traffic generation.

Defines schemas for attack ground-truth labels, victim degradation metrics,
and scenario generation parameters.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass(frozen=True)
class AttackLabel:
    """Ground truth label record for a generated attack scenario.

    Adheres to the data contract:
    start_ts,end_ts,src_ip,dst_ip,attack_type
    """

    start_ts: float
    end_ts: float
    src_ip: str
    dst_ip: str
    attack_type: str

    def to_csv_row(self) -> str:
        """Serialize label record to a CSV row format."""
        return f"{self.start_ts:.4f},{self.end_ts:.4f},{self.src_ip},{self.dst_ip},{self.attack_type}"


@dataclass(frozen=True)
class VictimMetric:
    """Per-second simulated telemetry recording victim host degradation during DoS.

    Attributes:
        timestamp: Epoch seconds of the measurement window.
        syn_ack_ratio: Observed ratio of completed handshakes vs SYN requests (0.0 - 1.0).
        response_delay_ms: Latency experienced by legitimate client probes in milliseconds.
        pps: Total packets per second received by the victim interface.
    """

    timestamp: float
    syn_ack_ratio: float
    response_delay_ms: float
    pps: float

    def to_csv_row(self) -> str:
        """Serialize telemetry metric to a CSV row format."""
        return f"{self.timestamp:.4f},{self.syn_ack_ratio:.4f},{self.response_delay_ms:.2f},{self.pps:.1f}"


@dataclass
class NetworkHost:
    """Simulated network endpoint definition."""

    ip: str
    mac: str
    hostname: str
    is_gateway: bool = False
    is_internal: bool = True


@dataclass
class GeneratorConfig:
    """Configuration options for synthetic traffic generation."""

    seed: int = 42
    simulated_duration_seconds: float = 900.0  # 15 minutes
    base_timestamp: float = 1700000000.0
    output_dir: Path = field(default_factory=lambda: Path("data/pcaps"))
    lan_subnet: str = "192.168.1.0/24"
    is_holdout: bool = False

