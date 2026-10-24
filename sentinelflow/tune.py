"""Threshold Tuning and False-Positive Calibration Module for SentinelFlow.

Sweeps detection rule thresholds across benign baseline network traffic to evaluate
and report false-positive (FP) rates for each candidate threshold value.
Enables defenders to establish empirical operating points that minimize alert fatigue
while maintaining high sensitivity to true attacks.
"""

import argparse
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pandas as pd
from rich.console import Console
from rich.table import Table

from sentinelflow.features import extract_window_features
from sentinelflow.parser import parse_pcap
from sentinelflow.rules import (
    detect_arp_spoofing,
    detect_port_scan,
    detect_ssh_bruteforce,
    detect_syn_flood,
    detect_udp_flood,
    load_rules_config,
    merge_adjacent_alerts,
)

logger = logging.getLogger(__name__)
console = Console()

DEFAULT_BENIGN_PCAP = Path("data/pcaps/s1_benign.pcap")
DEFAULT_CONFIG_PATH = Path("config/default.yaml")

# Default parameter search space for threshold calibration
DEFAULT_SWEEP_RANGES: Dict[str, Dict[str, List[Any]]] = {
    "port_scan": {
        "param": "min_unique_ports",
        "values": [3, 5, 8, 10, 15, 20, 25, 30, 40, 50],
    },
    "syn_flood": {
        "param": "syn_packet_rate_per_sec",
        "values": [10.0, 25.0, 50.0, 75.0, 100.0, 125.0, 150.0, 200.0],
    },
    "udp_flood": {
        "param": "udp_packet_rate_per_sec",
        "values": [20.0, 50.0, 80.0, 100.0, 125.0, 150.0, 200.0, 250.0],
    },
    "ssh_brute_force": {
        "param": "attempts_per_window",
        "values": [2, 3, 5, 7, 10, 12, 15, 20],
    },
    "arp_spoof": {
        "param": "unsolicited_reply_threshold",
        "values": [1, 2, 3, 5, 7, 10, 15],
    },
}


def sweep_thresholds(
    benign_windows_df: pd.DataFrame,
    benign_packets_df: Optional[pd.DataFrame] = None,
    sweep_ranges: Optional[Dict[str, Dict[str, List[Any]]]] = None,
    base_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, pd.DataFrame]:
    """Sweep threshold values across benign traffic to evaluate false-positive counts.

    Args:
        benign_windows_df: Feature DataFrame extracted strictly from benign baseline traffic.
        benign_packets_df: Optional parsed packets DataFrame from the benign capture.
        sweep_ranges: Dictionary mapping detector names to parameter name and candidate values.
        base_config: Baseline configuration dictionary (loads default.yaml if None).

    Returns:
        Dictionary mapping detector names to a DataFrame summarizing threshold sweep results.
    """
    if benign_windows_df.empty:
        logger.warning("Benign windows DataFrame is empty; cannot perform threshold calibration.")
        return {}

    cfg = base_config.copy() if base_config is not None else load_rules_config()
    ranges = sweep_ranges if sweep_ranges is not None else DEFAULT_SWEEP_RANGES
    total_windows = len(benign_windows_df)

    results: Dict[str, pd.DataFrame] = {}

    # 1. Port Scan Calibration
    if "port_scan" in ranges:
        param = ranges["port_scan"]["param"]
        vals = ranges["port_scan"]["values"]
        records = []
        for v in vals:
            test_cfg = {"port_scan": {**cfg.get("port_scan", {}), param: v, "enabled": True}}
            raw = detect_port_scan(benign_windows_df, test_cfg, benign_packets_df)
            merged = merge_adjacent_alerts(raw)
            fp_raw = len(raw)
            fp_merged = len(merged)
            records.append({
                "detector": "port_scan",
                "param": param,
                "value": v,
                "fp_windows": fp_raw,
                "fp_events": fp_merged,
                "fp_rate": fp_raw / total_windows if total_windows > 0 else 0.0,
            })
        results["port_scan"] = pd.DataFrame(records)

    # 2. SYN Flood Calibration
    if "syn_flood" in ranges:
        param = ranges["syn_flood"]["param"]
        vals = ranges["syn_flood"]["values"]
        records = []
        for v in vals:
            test_cfg = {"syn_flood": {**cfg.get("syn_flood", {}), param: v, "enabled": True}}
            raw = detect_syn_flood(benign_windows_df, test_cfg, benign_packets_df)
            merged = merge_adjacent_alerts(raw)
            fp_raw = len(raw)
            fp_merged = len(merged)
            records.append({
                "detector": "syn_flood",
                "param": param,
                "value": v,
                "fp_windows": fp_raw,
                "fp_events": fp_merged,
                "fp_rate": fp_raw / total_windows if total_windows > 0 else 0.0,
            })
        results["syn_flood"] = pd.DataFrame(records)

    # 3. UDP Flood Calibration
    if "udp_flood" in ranges:
        param = ranges["udp_flood"]["param"]
        vals = ranges["udp_flood"]["values"]
        records = []
        for v in vals:
            test_cfg = {"udp_flood": {**cfg.get("udp_flood", {}), param: v, "enabled": True}}
            raw = detect_udp_flood(benign_windows_df, test_cfg, benign_packets_df)
            merged = merge_adjacent_alerts(raw)
            fp_raw = len(raw)
            fp_merged = len(merged)
            records.append({
                "detector": "udp_flood",
                "param": param,
                "value": v,
                "fp_windows": fp_raw,
                "fp_events": fp_merged,
                "fp_rate": fp_raw / total_windows if total_windows > 0 else 0.0,
            })
        results["udp_flood"] = pd.DataFrame(records)

    # 4. SSH Brute Force Calibration
    if "ssh_brute_force" in ranges:
        param = ranges["ssh_brute_force"]["param"]
        vals = ranges["ssh_brute_force"]["values"]
        records = []
        for v in vals:
            test_cfg = {"ssh_brute_force": {**cfg.get("ssh_brute_force", {}), param: v, "enabled": True}}
            raw = detect_ssh_bruteforce(benign_windows_df, test_cfg, benign_packets_df)
            merged = merge_adjacent_alerts(raw)
            fp_raw = len(raw)
            fp_merged = len(merged)
            records.append({
                "detector": "ssh_brute_force",
                "param": param,
                "value": v,
                "fp_windows": fp_raw,
                "fp_events": fp_merged,
                "fp_rate": fp_raw / total_windows if total_windows > 0 else 0.0,
            })
        results["ssh_brute_force"] = pd.DataFrame(records)

    # 5. ARP Spoofing Calibration
    if "arp_spoof" in ranges:
        param = ranges["arp_spoof"]["param"]
        vals = ranges["arp_spoof"]["values"]
        records = []
        for v in vals:
            test_cfg = {"arp_spoof": {**cfg.get("arp_spoof", {}), param: v, "enabled": True}}
            raw = detect_arp_spoofing(benign_windows_df, test_cfg, benign_packets_df)
            merged = merge_adjacent_alerts(raw)
            fp_raw = len(raw)
            fp_merged = len(merged)
            records.append({
                "detector": "arp_spoof",
                "param": param,
                "value": v,
                "fp_windows": fp_raw,
                "fp_events": fp_merged,
                "fp_rate": fp_raw / total_windows if total_windows > 0 else 0.0,
            })
        results["arp_spoof"] = pd.DataFrame(records)

    return results


def format_sweep_tables(sweep_results: Dict[str, pd.DataFrame]) -> None:
    """Print formatted tables of threshold calibration results."""
    console.print("\n[bold cyan]=== SentinelFlow Threshold Calibration & False-Positive Audit ===[/bold cyan]\n")

    for detector_name, df in sweep_results.items():
        if df.empty:
            continue
        param = df["param"].iloc[0]
        table = Table(
            title=f"Detector: {detector_name.upper()} (Parameter: {param})",
            header_style="bold magenta",
        )
        table.add_column("Threshold Value", justify="right", style="cyan")
        table.add_column("FP Windows", justify="right")
        table.add_column("FP Events (Merged)", justify="right")
        table.add_column("FP Rate", justify="right", style="green")
        table.add_column("Status / Recommendation", justify="left")

        for _, row in df.iterrows():
            fp_events = int(row["fp_events"])
            fp_rate = float(row["fp_rate"])
            val_str = f"{row['value']:.1f}" if isinstance(row["value"], float) else str(row["value"])

            if fp_events == 0:
                status = "[bold green]Clean (0 FPs) - Recommended[/bold green]"
            elif fp_events <= 2:
                status = "[yellow]Low Risk - Borderline[/yellow]"
            else:
                status = f"[bold red]High False Positives ({fp_events} events)[/bold red]"

            table.add_row(
                val_str,
                str(int(row["fp_windows"])),
                str(fp_events),
                f"{fp_rate:.2%}",
                status,
            )

        console.print(table)
        console.print()


def run_tuning(
    pcap_path: Optional[Union[str, Path]] = None,
    config_path: Optional[Union[str, Path]] = None,
    window_size: float = 5.0,
) -> Dict[str, pd.DataFrame]:
    """Execute complete threshold calibration pipeline on benign network traffic.

    Args:
        pcap_path: Path to benign PCAP file (defaults to data/pcaps/s1_benign.pcap).
        config_path: Optional path to YAML configuration file.
        window_size: Window size in seconds for feature extraction.

    Returns:
        Dictionary of tuning results DataFrames.
    """
    path = Path(pcap_path) if pcap_path else DEFAULT_BENIGN_PCAP
    if not path.is_file():
        raise FileNotFoundError(f"Benign PCAP file not found at: {path.resolve()}")

    console.print(f"[bold]Parsing benign PCAP trace:[/bold] {path}")
    pkts_df = parse_pcap(path)
    console.print(f"[green]Parsed {len(pkts_df):,} packets.[/green] Extracting {window_size}s window features...")

    win_df = extract_window_features(pkts_df, window_size=window_size)
    console.print(f"[green]Extracted {len(win_df):,} per-source traffic windows.[/green] Sweeping thresholds...\n")

    base_cfg = load_rules_config(config_path)
    sweep_results = sweep_thresholds(win_df, pkts_df, base_config=base_cfg)
    format_sweep_tables(sweep_results)
    return sweep_results


def main() -> None:
    """CLI entry point for threshold tuning."""
    parser = argparse.ArgumentParser(description="SentinelFlow Rule Threshold Calibration Tool")
    parser.add_argument(
        "--pcap",
        type=str,
        default=str(DEFAULT_BENIGN_PCAP),
        help="Path to benign baseline PCAP file",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=str(DEFAULT_CONFIG_PATH),
        help="Path to default.yaml configuration",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=5.0,
        help="Window duration in seconds (default: 5.0)",
    )
    args = parser.parse_args()

    run_tuning(pcap_path=args.pcap, config_path=args.config, window_size=args.window)


if __name__ == "__main__":
    main()
