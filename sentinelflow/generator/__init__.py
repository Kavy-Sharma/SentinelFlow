"""Synthetic traffic and PCAP generation module for SentinelFlow.

Provides deterministic, reproducible generation of benign baseline network traffic
and synthetic malicious attack scenarios (Port Scan, SYN/UDP Floods, SSH Brute Force, ARP Spoofing).
"""

from sentinelflow.generator.attacks import (
    generate_arp_spoofing,
    generate_benign_backup_flash_crowd,
    generate_distributed_slow_scan,
    generate_fast_syn_port_scan,
    generate_slow_port_scan,
    generate_ssh_brute_force,
    generate_syn_flood,
    generate_syn_flood_spoofed,
    generate_udp_flood,
    generate_victim_telemetry,
)
from sentinelflow.generator.benign import (
    build_default_network,
    generate_benign_traffic,
    generate_dns_exchange,
    generate_icmp_ping_burst,
    generate_ssh_long_session,
    generate_tcp_session,
)
from sentinelflow.generator.engine import ScenarioGenerator, write_dataset_files, write_victim_metrics_csv
from sentinelflow.generator.models import AttackLabel, GeneratorConfig, NetworkHost, VictimMetric

__all__ = [
    "AttackLabel",
    "VictimMetric",
    "NetworkHost",
    "GeneratorConfig",
    "ScenarioGenerator",
    "write_dataset_files",
    "write_victim_metrics_csv",
    "build_default_network",
    "generate_benign_traffic",
    "generate_dns_exchange",
    "generate_tcp_session",
    "generate_ssh_long_session",
    "generate_icmp_ping_burst",
    "generate_fast_syn_port_scan",
    "generate_slow_port_scan",
    "generate_syn_flood",
    "generate_syn_flood_spoofed",
    "generate_udp_flood",
    "generate_victim_telemetry",
    "generate_ssh_brute_force",
    "generate_arp_spoofing",
    "generate_benign_backup_flash_crowd",
    "generate_distributed_slow_scan",
]
