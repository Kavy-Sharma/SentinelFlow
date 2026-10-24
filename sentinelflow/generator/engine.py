"""Orchestration engine for generating synthetic PCAP datasets and ground-truth labels.

Handles:
- Mixing benign enterprise background traffic with targeted attack overlays
- Monotonic sorting of all packet timestamps prior to serialization
- Exporting raw .pcap captures via Scapy's wrpcap
- Writing matching labels CSVs adhering to the contract:
  start_ts,end_ts,src_ip,dst_ip,attack_type
- Writing victim host degradation metrics (victim_metrics.csv) for DoS evaluation
- Producing holdout datasets with independent random seeds and varied parameters
"""

import logging
import random
from pathlib import Path
from typing import Dict, List, Optional

from scapy.packet import Packet
from scapy.utils import wrpcap

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
from sentinelflow.generator.benign import build_default_network, generate_benign_traffic
from sentinelflow.generator.models import AttackLabel, GeneratorConfig, VictimMetric

logger = logging.getLogger(__name__)


def write_dataset_files(
    pcap_path: Path,
    labels_path: Path,
    packets: List[Packet],
    labels: List[AttackLabel],
) -> None:
    """Sort packets by timestamp and serialize PCAP and ground-truth CSV files.

    Args:
        pcap_path: Target path for .pcap file.
        labels_path: Target path for matching labels .csv.
        packets: List of Scapy packets to write.
        labels: Ground-truth attack intervals.
    """
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    labels_path.parent.mkdir(parents=True, exist_ok=True)

    # Enforce strictly monotonic timestamp ordering
    packets.sort(key=lambda p: float(p.time))

    logger.info("Writing %d packets to %s", len(packets), pcap_path)
    wrpcap(str(pcap_path), packets)

    with open(labels_path, "w", encoding="utf-8") as f:
        f.write("start_ts,end_ts,src_ip,dst_ip,attack_type\n")
        for label in labels:
            f.write(label.to_csv_row() + "\n")
    logger.info("Saved %d labels to %s", len(labels), labels_path)


def write_victim_metrics_csv(csv_path: Path, metrics: List[VictimMetric]) -> None:
    """Write victim host performance degradation telemetry to CSV.

    Args:
        csv_path: Target CSV path.
        metrics: List of per-second telemetry records.
    """
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write("timestamp,syn_ack_ratio,response_delay_ms,pps\n")
        for m in metrics:
            f.write(m.to_csv_row() + "\n")
    logger.info("Saved %d victim metrics to %s", len(metrics), csv_path)


class ScenarioGenerator:
    """Orchestrates scenario dataset generation for SentinelFlow."""

    def __init__(self, config: GeneratorConfig) -> None:
        """Initialize scenario generator with configuration.

        Args:
            config: GeneratorConfig holding random seed, output directory, and duration.
        """
        self.config = config
        self.rng = random.Random(config.seed)
        self.workstations, self.gateway, self.app_server, self.external_ips = build_default_network()

    def generate_s1_benign(self) -> Dict[str, Path]:
        """Generate Scenario 1: Pure benign baseline enterprise traffic.

        Returns:
            Dictionary of created file paths.
        """
        out_dir = self.config.output_dir
        pcap_file = out_dir / "s1_benign.pcap"
        labels_file = out_dir / "s1_benign_labels.csv"

        packets = generate_benign_traffic(self.config)
        labels: List[AttackLabel] = []

        write_dataset_files(pcap_file, labels_file, packets, labels)
        return {"pcap": pcap_file, "labels": labels_file}

    def generate_s2_port_scan(self) -> Dict[str, Path]:
        """Generate Scenario 2: Fast SYN scan and slow stealth scan overlaid on benign traffic.

        Returns:
            Dictionary of created file paths.
        """
        out_dir = self.config.output_dir
        results: Dict[str, Path] = {}

        # 1. Fast SYN Port Scan (1000 ports)
        benign_packets = generate_benign_traffic(self.config)
        is_holdout = self.config.is_holdout or self.config.seed != 42
        attacker_ip = "192.168.1.88" if is_holdout else "192.168.1.99"
        attacker_mac = "00:16:3e:aa:bb:ee" if is_holdout else "00:16:3e:aa:bb:01"
        attack_start = self.config.base_timestamp + (145.0 if is_holdout else 120.0)

        scan_pkts, scan_label = generate_fast_syn_port_scan(
            attacker_ip=attacker_ip,
            attacker_mac=attacker_mac,
            victim_ip=self.app_server.ip,
            victim_mac=self.app_server.mac,
            start_time=attack_start,
            port_count=1000,
            rng=random.Random(self.config.seed + 1),
        )

        pcap_fast = out_dir / "s2_port_scan.pcap"
        labels_fast = out_dir / "s2_port_scan_labels.csv"
        write_dataset_files(pcap_fast, labels_fast, benign_packets + scan_pkts, [scan_label])
        results["fast_pcap"] = pcap_fast
        results["fast_labels"] = labels_fast

        # 2. Slow Stealth Port Scan
        benign_slow = generate_benign_traffic(self.config)
        slow_pkts, slow_label = generate_slow_port_scan(
            attacker_ip=attacker_ip,
            attacker_mac=attacker_mac,
            victim_ip=self.app_server.ip,
            victim_mac=self.app_server.mac,
            start_time=self.config.base_timestamp + 90.0,
            port_count=80,
            rng=random.Random(self.config.seed + 2),
        )

        pcap_slow = out_dir / "s2_slow_scan.pcap"
        labels_slow = out_dir / "s2_slow_scan_labels.csv"
        write_dataset_files(pcap_slow, labels_slow, benign_slow + slow_pkts, [slow_label])
        results["slow_pcap"] = pcap_slow
        results["slow_labels"] = labels_slow

        return results

    def generate_s3_dos(self) -> Dict[str, Path]:
        """Generate Scenario 3: SYN floods (single and spoofed) and UDP flood + victim metrics.

        Returns:
            Dictionary of created file paths.
        """
        out_dir = self.config.output_dir
        results: Dict[str, Path] = {}
        is_holdout = self.config.is_holdout or self.config.seed != 42
        attacker_ip = "192.168.1.144" if is_holdout else "192.168.1.150"
        attacker_mac = "00:16:3e:cc:dd:ee" if is_holdout else "00:16:3e:cc:dd:01"
        attack_start = self.config.base_timestamp + (195.0 if is_holdout else 180.0)
        attack_duration = 30.0 if is_holdout else 35.0
        rate_pps = 160.0 if is_holdout else 140.0

        # 1. SYN Flood (Randomized Source Ports)
        benign_1 = generate_benign_traffic(self.config)
        syn_pkts, syn_label = generate_syn_flood(
            attacker_ip=attacker_ip,
            attacker_mac=attacker_mac,
            victim_ip=self.app_server.ip,
            victim_mac=self.app_server.mac,
            target_port=80,
            start_time=attack_start,
            duration=attack_duration,
            rate_pps=rate_pps,
            rng=random.Random(self.config.seed + 10),
        )
        pcap_syn = out_dir / "s3_syn_flood.pcap"
        labels_syn = out_dir / "s3_syn_flood_labels.csv"
        write_dataset_files(pcap_syn, labels_syn, benign_1 + syn_pkts, [syn_label])
        results["syn_flood_pcap"] = pcap_syn
        results["syn_flood_labels"] = labels_syn

        # 2. Spoofed Source SYN Flood
        benign_2 = generate_benign_traffic(self.config)
        spoofed_pkts, spoofed_label = generate_syn_flood_spoofed(
            victim_ip=self.app_server.ip,
            victim_mac=self.app_server.mac,
            gateway_mac=self.gateway.mac,
            target_port=80,
            start_time=attack_start,
            duration=attack_duration,
            rate_pps=140.0,
            rng=random.Random(self.config.seed + 11),
        )
        pcap_spoofed = out_dir / "s3_syn_flood_spoofed.pcap"
        labels_spoofed = out_dir / "s3_syn_flood_spoofed_labels.csv"
        write_dataset_files(pcap_spoofed, labels_spoofed, benign_2 + spoofed_pkts, [spoofed_label])
        results["syn_spoofed_pcap"] = pcap_spoofed
        results["syn_spoofed_labels"] = labels_spoofed

        # 3. UDP Flood
        benign_3 = generate_benign_traffic(self.config)
        udp_pkts, udp_label = generate_udp_flood(
            attacker_ip=attacker_ip,
            attacker_mac=attacker_mac,
            victim_ip=self.app_server.ip,
            victim_mac=self.app_server.mac,
            start_time=attack_start,
            duration=25.0,
            rate_pps=150.0,
            rng=random.Random(self.config.seed + 12),
        )
        pcap_udp = out_dir / "s3_udp_flood.pcap"
        labels_udp = out_dir / "s3_udp_flood_labels.csv"
        write_dataset_files(pcap_udp, labels_udp, benign_3 + udp_pkts, [udp_label])
        results["udp_flood_pcap"] = pcap_udp
        results["udp_flood_labels"] = labels_udp

        # 4. Victim Metrics CSV
        metrics = generate_victim_telemetry(
            attack_start_time=180.0,
            attack_duration=attack_duration,
            total_duration=min(self.config.simulated_duration_seconds, 360.0),
            rng=random.Random(self.config.seed + 13),
        )
        metrics_csv = out_dir / "victim_metrics.csv"
        write_victim_metrics_csv(metrics_csv, metrics)
        results["victim_metrics"] = metrics_csv

        return results

    def generate_s4_additional(self) -> Dict[str, Path]:
        """Generate Scenario 4: SSH Brute Force and ARP Spoofing overlaid on benign traffic.

        Returns:
            Dictionary of created file paths.
        """
        out_dir = self.config.output_dir
        results: Dict[str, Path] = {}

        # 1. SSH Brute Force
        benign_1 = generate_benign_traffic(self.config)
        is_holdout = self.config.is_holdout or self.config.seed != 42
        ssh_attacker = "192.168.1.177" if is_holdout else "192.168.1.180"
        ssh_mac = "00:16:3e:bb:cc:ee" if is_holdout else "00:16:3e:bb:cc:01"
        ssh_pkts, ssh_label = generate_ssh_brute_force(
            attacker_ip=ssh_attacker,
            attacker_mac=ssh_mac,
            victim_ip=self.app_server.ip,
            victim_mac=self.app_server.mac,
            start_time=self.config.base_timestamp + (115.0 if is_holdout else 100.0),
            attempts=35 if is_holdout else 40,
            rng=random.Random(self.config.seed + 20),
        )
        pcap_ssh = out_dir / "s4_ssh_brute_force.pcap"
        labels_ssh = out_dir / "s4_ssh_brute_force_labels.csv"
        write_dataset_files(pcap_ssh, labels_ssh, benign_1 + ssh_pkts, [ssh_label])
        results["ssh_brute_pcap"] = pcap_ssh
        results["ssh_brute_labels"] = labels_ssh

        # 2. ARP Spoofing (Gateway MitM)
        benign_2 = generate_benign_traffic(self.config)
        arp_attacker = "192.168.1.195" if is_holdout else "192.168.1.199"
        arp_attacker_mac = "00:16:3e:ba:dd:ee" if is_holdout else "00:16:3e:ba:dd:01"
        arp_pkts, arp_label = generate_arp_spoofing(
            attacker_ip=arp_attacker,
            attacker_mac=arp_attacker_mac,
            gateway_ip=self.gateway.ip,
            victim_ip=self.app_server.ip,
            victim_mac=self.app_server.mac,
            start_time=self.config.base_timestamp + (165.0 if is_holdout else 150.0),
            duration=50.0 if is_holdout else 60.0,
            interval_seconds=1.2 if is_holdout else 1.5,
            rng=random.Random(self.config.seed + 21),
        )
        pcap_arp = out_dir / "s4_arp_spoof.pcap"
        labels_arp = out_dir / "s4_arp_spoof_labels.csv"
        write_dataset_files(pcap_arp, labels_arp, benign_2 + arp_pkts, [arp_label])
        results["arp_spoof_pcap"] = pcap_arp
        results["arp_spoof_labels"] = labels_arp

        return results

    def generate_s5_ambiguous(self) -> Dict[str, Path]:
        """Generate Scenario 5: Benign enterprise backup / flash crowd and distributed slow scan.

        Returns:
            Dictionary of created file paths.
        """
        out_dir = self.config.output_dir
        results: Dict[str, Path] = {}

        # 1. Benign Flash Crowd / Scheduled Backup
        benign_1 = generate_benign_traffic(self.config)
        backup_pkts, backup_label = generate_benign_backup_flash_crowd(
            source_host=self.workstations[3],
            destination_host=self.app_server,
            start_time=self.config.base_timestamp + 200.0,
            duration=35.0,
            rate_pps=160.0,
            rng=random.Random(self.config.seed + 30),
        )
        pcap_backup = out_dir / "s5_flash_crowd.pcap"
        labels_backup = out_dir / "s5_flash_crowd_labels.csv"
        write_dataset_files(pcap_backup, labels_backup, benign_1 + backup_pkts, [backup_label])
        results["flash_crowd_pcap"] = pcap_backup
        results["flash_crowd_labels"] = labels_backup

        # 2. Distributed Slow Scan
        benign_2 = generate_benign_traffic(self.config)
        dist_pkts, dist_label = generate_distributed_slow_scan(
            victim_ip=self.app_server.ip,
            victim_mac=self.app_server.mac,
            start_time=self.config.base_timestamp + 80.0,
            source_count=5,
            ports_per_source=4,
            rng=random.Random(self.config.seed + 31),
        )
        pcap_dist = out_dir / "s5_distributed_slow_scan.pcap"
        labels_dist = out_dir / "s5_distributed_slow_scan_labels.csv"
        write_dataset_files(pcap_dist, labels_dist, benign_2 + dist_pkts, [dist_label])
        results["dist_scan_pcap"] = pcap_dist
        results["dist_scan_labels"] = labels_dist

        return results

    def generate_all(self) -> Dict[str, Path]:
        """Generate all scenarios (S1 through S5).

        Returns:
            Combined dictionary of all generated file paths.
        """
        all_results: Dict[str, Path] = {}
        logger.info("Executing Scenario 1: Benign Baseline...")
        all_results.update(self.generate_s1_benign())

        logger.info("Executing Scenario 2: Port Scanning...")
        all_results.update(self.generate_s2_port_scan())

        logger.info("Executing Scenario 3: Denial of Service...")
        all_results.update(self.generate_s3_dos())

        logger.info("Executing Scenario 4: Additional Attacks...")
        all_results.update(self.generate_s4_additional())

        logger.info("Executing Scenario 5: Ambiguous Traffic...")
        all_results.update(self.generate_s5_ambiguous())

        logger.info("All scenarios generated successfully into %s", self.config.output_dir)
        return all_results
