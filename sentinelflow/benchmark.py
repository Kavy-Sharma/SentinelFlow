"""Performance and Throughput Benchmarking Module for SentinelFlow.

Profiles PCAP parsing speed (packets/sec, MB/sec), feature extraction latency,
rule execution time, ML scoring latency, and end-to-end detection pipeline throughput.
"""

from dataclasses import dataclass
import gc
import logging
from pathlib import Path
import time
import tracemalloc
from typing import Any, Dict, List, Optional, Union

import pandas as pd

from sentinelflow.features import extract_window_features
from sentinelflow.fusion import fuse_detections
from sentinelflow.ml import IsolationForestAnomalyDetector
from sentinelflow.parser import parse_pcap
from sentinelflow.rules import detect_all_rules

logger = logging.getLogger(__name__)

DEFAULT_BENCHMARK_PCAPS = [
    Path("data/pcaps/s1_benign.pcap"),
    Path("data/pcaps/s2_port_scan.pcap"),
    Path("data/pcaps/s3_syn_flood.pcap"),
]
DEFAULT_MODEL_PATH = Path("models/isolation_forest.joblib")


@dataclass
class BenchmarkMetric:
    """Benchmark performance metrics for a single PCAP."""

    pcap_name: str
    file_size_bytes: int
    packet_count: int
    window_count: int
    parse_time_sec: float
    feature_time_sec: float
    detection_time_sec: float
    total_time_sec: float
    packet_throughput_pps: float
    byte_throughput_mb_s: float
    peak_memory_mb: float


def benchmark_pcap(
    pcap_path: Union[str, Path],
    model_path: Optional[Union[str, Path]] = DEFAULT_MODEL_PATH,
    window_size: float = 5.0,
) -> BenchmarkMetric:
    """Benchmark end-to-end processing pipeline on a single PCAP file.

    Args:
        pcap_path: Path to the target PCAP file.
        model_path: Optional path to serialized ML model.
        window_size: Window duration in seconds.

    Returns:
        BenchmarkMetric dataclass with detailed timings and throughput.
    """
    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    file_size = path.stat().st_size
    gc.collect()
    tracemalloc.start()

    # 1. PCAP Parsing Stage
    t0 = time.perf_counter()
    packets_df = parse_pcap(path)
    t1 = time.perf_counter()
    parse_sec = max(1e-4, t1 - t0)

    # 2. Feature Extraction Stage
    t2 = time.perf_counter()
    windows_df = extract_window_features(packets_df, window_size=window_size)
    t3 = time.perf_counter()
    feature_sec = max(1e-4, t3 - t2)

    # 3. Detection & Fusion Stage
    ml_detector = None
    if model_path and Path(model_path).is_file():
        ml_detector = IsolationForestAnomalyDetector.load(model_path)

    t4 = time.perf_counter()
    rule_alerts = detect_all_rules(windows_df, packets_df=packets_df, merge_events=True)
    alerts = fuse_detections(
        rule_alerts=rule_alerts,
        windows_df=windows_df,
        ml_detector=ml_detector,
        packets_df=packets_df,
    )
    t5 = time.perf_counter()
    detect_sec = max(1e-4, t5 - t4)

    total_sec = parse_sec + feature_sec + detect_sec
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    pkt_count = len(packets_df)
    win_count = len(windows_df)
    pps = pkt_count / total_sec if total_sec > 0 else 0.0
    mb_s = (file_size / (1024 * 1024)) / total_sec if total_sec > 0 else 0.0
    peak_mb = peak_bytes / (1024 * 1024)

    return BenchmarkMetric(
        pcap_name=path.name,
        file_size_bytes=file_size,
        packet_count=pkt_count,
        window_count=win_count,
        parse_time_sec=parse_sec,
        feature_time_sec=feature_sec,
        detection_time_sec=detect_sec,
        total_time_sec=total_sec,
        packet_throughput_pps=pps,
        byte_throughput_mb_s=mb_s,
        peak_memory_mb=peak_mb,
    )


def run_benchmarks(
    pcap_paths: Optional[List[Union[str, Path]]] = None,
    model_path: Optional[Union[str, Path]] = DEFAULT_MODEL_PATH,
) -> List[BenchmarkMetric]:
    """Run benchmark profiling across multiple PCAPs."""
    paths = pcap_paths or [p for p in DEFAULT_BENCHMARK_PCAPS if p.is_file()]
    if not paths:
        # Fallback to any pcaps in data/pcaps
        fallback_dir = Path("data/pcaps")
        paths = sorted(fallback_dir.glob("*.pcap"))[:3]

    results: List[BenchmarkMetric] = []
    for p in paths:
        results.append(benchmark_pcap(p, model_path=model_path))

    return results
