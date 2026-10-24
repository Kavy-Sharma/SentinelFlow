"""Unit tests for synthetic traffic and PCAP generation.

Validates:
- Deterministic reproducibility for identical random seeds
- Monotonic timestamp ordering across all generated packets
- Non-empty PCAP files parseable by Scapy rdpcap
- Validity and completeness of ground-truth attack labels (start_ts <= end_ts)
- S3 victim performance telemetry metrics during denial of service
- Holdout dataset parameter divergence for generalization testing
"""

from pathlib import Path

import pytest
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.utils import rdpcap

from sentinelflow.generator.benign import generate_benign_traffic
from sentinelflow.generator.engine import ScenarioGenerator
from sentinelflow.generator.models import GeneratorConfig


def test_generator_determinism() -> None:
    """Verify that running generation with identical seed yields bit-for-bit identical packets."""
    config1 = GeneratorConfig(seed=42, simulated_duration_seconds=60.0)
    config2 = GeneratorConfig(seed=42, simulated_duration_seconds=60.0)

    pkts1 = generate_benign_traffic(config1)
    pkts2 = generate_benign_traffic(config2)

    assert len(pkts1) == len(pkts2), "Packet counts must match for identical seed"
    for p1, p2 in zip(pkts1, pkts2):
        assert float(p1.time) == float(p2.time), "Packet timestamps must match exactly"
        assert bytes(p1) == bytes(p2), "Raw packet byte serialization must be identical"


def test_monotonic_timestamps() -> None:
    """Verify all packets have non-decreasing, strictly monotonic timestamps."""
    config = GeneratorConfig(seed=42, simulated_duration_seconds=120.0)
    packets = generate_benign_traffic(config)

    assert len(packets) > 0, "Generated packet list should not be empty"
    for i in range(len(packets) - 1):
        assert (
            packets[i].time <= packets[i + 1].time
        ), f"Timestamp inversion at index {i}: {packets[i].time} > {packets[i+1].time}"


def test_benign_protocol_diversity() -> None:
    """Verify benign traffic contains realistic distribution of HTTP/HTTPS, DNS, and ICMP."""
    config = GeneratorConfig(seed=42, simulated_duration_seconds=180.0)
    packets = generate_benign_traffic(config)

    has_tcp = any(p.haslayer(TCP) for p in packets)
    has_udp_dns = any(p.haslayer(UDP) and p.haslayer(DNS) for p in packets)
    has_icmp = any(p.haslayer(ICMP) for p in packets)

    assert has_tcp, "Benign traffic must contain TCP sessions"
    assert has_udp_dns, "Benign traffic must contain DNS resolution traffic"
    assert has_icmp, "Benign traffic must contain ICMP diagnostics"


def test_scenario_execution_and_labels(tmp_path: Path) -> None:
    """Verify S1 through S5 produce valid PCAPs and labels matching the data contract."""
    config = GeneratorConfig(
        seed=42,
        simulated_duration_seconds=120.0,
        output_dir=tmp_path,
    )
    generator = ScenarioGenerator(config)

    # 1. Scenario 1 (Benign)
    s1_files = generator.generate_s1_benign()
    assert s1_files["pcap"].exists() and s1_files["pcap"].stat().st_size > 0
    assert s1_files["labels"].exists()
    s1_pkts = rdpcap(str(s1_files["pcap"]))
    assert len(s1_pkts) > 0

    # 2. Scenario 2 (Port Scans)
    s2_files = generator.generate_s2_port_scan()
    for key, pcap_path in [("fast_pcap", s2_files["fast_pcap"]), ("slow_pcap", s2_files["slow_pcap"])]:
        assert pcap_path.exists() and pcap_path.stat().st_size > 0
        pkts = rdpcap(str(pcap_path))
        assert len(pkts) > 0

    # Validate S2 labels CSV
    labels_content = s2_files["fast_labels"].read_text(encoding="utf-8").strip().splitlines()
    assert labels_content[0] == "start_ts,end_ts,src_ip,dst_ip,attack_type"
    assert len(labels_content) == 2
    start_ts, end_ts, src, dst, attack_type = labels_content[1].split(",")
    assert float(start_ts) <= float(end_ts)
    assert attack_type == "port_scan"
    assert src == "192.168.1.99"

    # 3. Scenario 3 (DoS)
    s3_files = generator.generate_s3_dos()
    for k in ["syn_flood_pcap", "syn_spoofed_pcap", "udp_flood_pcap"]:
        pcap = s3_files[k]
        assert pcap.exists() and pcap.stat().st_size > 0
        assert len(rdpcap(str(pcap))) > 0

    # Validate victim metrics CSV
    metrics_file = s3_files["victim_metrics"]
    assert metrics_file.exists() and metrics_file.stat().st_size > 0
    metric_lines = metrics_file.read_text(encoding="utf-8").strip().splitlines()
    assert metric_lines[0] == "timestamp,syn_ack_ratio,response_delay_ms,pps"
    assert len(metric_lines) > 10

    # 4. Scenario 4 (SSH Brute Force & ARP Spoof)
    s4_files = generator.generate_s4_additional()
    for k in ["ssh_brute_pcap", "arp_spoof_pcap"]:
        pcap = s4_files[k]
        assert pcap.exists() and pcap.stat().st_size > 0
        assert len(rdpcap(str(pcap))) > 0

    # Validate ARP Spoof labels
    arp_labels = s4_files["arp_spoof_labels"].read_text(encoding="utf-8").strip().splitlines()
    assert len(arp_labels) == 2
    _, _, arp_src, _, arp_type = arp_labels[1].split(",")
    assert arp_src == "192.168.1.199"
    assert arp_type == "arp_spoofing"

    # 5. Scenario 5 (Ambiguous)
    s5_files = generator.generate_s5_ambiguous()
    for k in ["flash_crowd_pcap", "dist_scan_pcap"]:
        pcap = s5_files[k]
        assert pcap.exists() and pcap.stat().st_size > 0
        assert len(rdpcap(str(pcap))) > 0


def test_holdout_parameter_divergence(tmp_path: Path) -> None:
    """Verify holdout dataset generation employs distinct attacker parameters."""
    default_cfg = GeneratorConfig(seed=42, output_dir=tmp_path / "default", is_holdout=False)
    holdout_cfg = GeneratorConfig(seed=1337, output_dir=tmp_path / "holdout", is_holdout=True)

    gen_def = ScenarioGenerator(default_cfg)
    gen_hld = ScenarioGenerator(holdout_cfg)

    def_s2 = gen_def.generate_s2_port_scan()
    hld_s2 = gen_hld.generate_s2_port_scan()

    def_label_row = def_s2["fast_labels"].read_text().splitlines()[1]
    hld_label_row = hld_s2["fast_labels"].read_text().splitlines()[1]

    # Holdout should have a distinct attacker IP (192.168.1.88 vs 192.168.1.99)
    assert "192.168.1.99" in def_label_row
    assert "192.168.1.88" in hld_label_row
