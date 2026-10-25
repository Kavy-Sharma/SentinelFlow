"""Detection Accuracy Evaluation and Benchmark Metrics Module for SentinelFlow.

Evaluates detection performance across PCAP captures and ground-truth labeled scenarios.
Computes True Positives, False Positives, False Negatives, Precision, Recall, F1-Score,
and per-scenario detection metrics.
"""

from dataclasses import dataclass
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd

from sentinelflow.features import extract_window_features, label_windows
from sentinelflow.fusion import fuse_detections
from sentinelflow.ml import IsolationForestAnomalyDetector
from sentinelflow.parser import parse_pcap
from sentinelflow.rules import detect_all_rules

logger = logging.getLogger(__name__)

DEFAULT_PCAPS_DIR = Path("data/pcaps")
DEFAULT_HOLDOUT_DIR = Path("data/pcaps_holdout")
DEFAULT_MODEL_PATH = Path("models/isolation_forest.joblib")


@dataclass
class ScenarioEvaluation:
    """Evaluation result record for a single PCAP scenario."""

    scenario: str
    pcap_path: str
    total_windows: int
    malicious_windows: int
    detected_alerts_count: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    f1: float
    accuracy: float
    attack_detected: bool
    detected_attack_types: List[str]
    window_tp: int = 0
    window_fp: int = 0
    window_fn: int = 0
    window_tn: int = 0
    window_precision: float = 0.0
    window_recall: float = 0.0
    window_f1: float = 0.0
    window_accuracy: float = 0.0


KNOWN_ATTACK_TYPES = {
    "port_scan",
    "slow_scan",
    "syn_flood",
    "syn_flood_spoofed",
    "udp_flood",
    "arp_spoofing",
    "ssh_brute_force",
    "distributed_slow_scan",
}


def evaluate_dataset(
    pcaps_dir: Union[str, Path] = DEFAULT_PCAPS_DIR,
    model_path: Optional[Union[str, Path]] = DEFAULT_MODEL_PATH,
    mode: str = "hybrid",
    window_size: float = 5.0,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Evaluate detection engine across all PCAP files and matching ground-truth CSVs in a directory.

    Evaluates performance at both:
    1. Incident / Scenario Level: Binary detection classification per PCAP capture.
    2. Window Level: Fine-grained temporal / source-entity window attribution.

    Args:
        pcaps_dir: Directory containing .pcap files and *_labels.csv files.
        model_path: Path to serialized Isolation Forest artifact (optional).
        mode: Detection mode ('hybrid', 'rules', 'ml').
        window_size: Aggregation window size in seconds.
        config: Optional detection configuration dict.

    Returns:
        Dictionary with overall metrics and per-scenario breakdowns.
    """
    directory = Path(pcaps_dir)
    pcap_files = sorted(directory.glob("*.pcap"))
    if not pcap_files:
        raise FileNotFoundError(f"No PCAP files found in '{directory}'.")

    # Load ML detector if needed
    ml_detector: Optional[IsolationForestAnomalyDetector] = None
    if mode in ("hybrid", "ml") and model_path:
        m_path = Path(model_path)
        if m_path.is_file():
            ml_detector = IsolationForestAnomalyDetector.load(m_path)
        else:
            logger.warning("ML model artifact not found at %s; proceeding with rules only.", m_path)

    scenario_results: List[ScenarioEvaluation] = []
    total_tp = 0
    total_fp = 0
    total_fn = 0
    total_tn = 0

    tot_win_tp = 0
    tot_win_fp = 0
    tot_win_fn = 0
    tot_win_tn = 0

    for pcap_file in pcap_files:
        lbl_file = directory / f"{pcap_file.stem}_labels.csv"
        pkts = parse_pcap(pcap_file)
        wins = extract_window_features(pkts, window_size=window_size)

        # Ground truth
        lbl_df = pd.read_csv(lbl_file) if lbl_file.is_file() else pd.DataFrame()
        labeled_wins = label_windows(wins, lbl_df)

        # Identify genuine attack scenarios (excluding benign enterprise captures like benign_backup)
        is_attack_scenario = (
            not lbl_df.empty
            and "attack_type" in lbl_df.columns
            and lbl_df["attack_type"].isin(KNOWN_ATTACK_TYPES).any()
        )

        # Execute Detectors according to mode
        rule_alerts = []
        if mode in ("hybrid", "rules"):
            rule_alerts = detect_all_rules(wins, packets_df=pkts, config=config, merge_events=True)

        if mode == "rules":
            alerts = [a.to_explanation() for a in rule_alerts]
        else:
            alerts = fuse_detections(
                rule_alerts=rule_alerts,
                windows_df=wins,
                ml_detector=ml_detector,
                config=config,
                packets_df=pkts,
            )

        # Identify ground-truth malicious windows
        true_mal_mask = (
            labeled_wins["attack_type"].isin(KNOWN_ATTACK_TYPES)
            if "attack_type" in labeled_wins.columns
            else pd.Series(False, index=labeled_wins.index)
        )
        malicious_count = int(true_mal_mask.sum())

        detected_types = list({a.mitre_technique_name or a.detector_name for a in alerts})

        # 1. Incident / Scenario-Level Metrics (Binary scenario classification):
        if is_attack_scenario:
            if len(alerts) > 0:
                tp = 1
                fp = 0
                fn = 0
                tn = 0
            else:
                tp = 0
                fp = 0
                fn = 1
                tn = 0
        else:
            if len(alerts) > 0:
                tp = 0
                fp = 1
                fn = 0
                tn = 0
            else:
                tp = 0
                fp = 0
                fn = 0
                tn = 1

        prec = float(tp / (tp + fp)) if (tp + fp) > 0 else (1.0 if not is_attack_scenario and fp == 0 else 0.0)
        rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 1.0
        f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        acc = float((tp + tn) / (tp + tn + fp + fn)) if (tp + tn + fp + fn) > 0 else 0.0

        total_tp += tp
        total_fp += fp
        total_fn += fn
        total_tn += tn

        # 2. Window-Level Metrics (Fine-grained temporal/entity attribution):
        flagged_mask = np.zeros(len(wins), dtype=bool)
        for a in alerts:
            t_start = a.timestamp if a.timestamp is not None else 0.0
            t_end = a.window_end if a.window_end is not None else (t_start + (a.duration or window_size))
            if a.source_ip:
                m = (wins["src_ip"] == a.source_ip) & (wins["win_start"] < t_end) & (wins["win_end"] > t_start)
            else:
                m = (wins["win_start"] < t_end) & (wins["win_end"] > t_start)
            flagged_mask |= m.values

        w_tp = int((true_mal_mask & flagged_mask).sum())
        w_fp = int((~true_mal_mask & flagged_mask).sum())
        w_fn = int((true_mal_mask & ~flagged_mask).sum())
        w_tn = int((~true_mal_mask & ~flagged_mask).sum())

        w_prec = float(w_tp / (w_tp + w_fp)) if (w_tp + w_fp) > 0 else 0.0
        w_rec = float(w_tp / (w_tp + w_fn)) if (w_tp + w_fn) > 0 else (1.0 if malicious_count == 0 else 0.0)
        w_f1 = float(2 * w_prec * w_rec / (w_prec + w_rec)) if (w_prec + w_rec) > 0 else 0.0
        w_acc = float((w_tp + w_tn) / len(wins)) if len(wins) > 0 else 0.0

        tot_win_tp += w_tp
        tot_win_fp += w_fp
        tot_win_fn += w_fn
        tot_win_tn += w_tn

        scenario_results.append(
            ScenarioEvaluation(
                scenario=pcap_file.stem,
                pcap_path=str(pcap_file),
                total_windows=len(wins),
                malicious_windows=malicious_count,
                detected_alerts_count=len(alerts),
                true_positives=tp,
                false_positives=fp,
                false_negatives=fn,
                true_negatives=tn,
                precision=prec,
                recall=rec,
                f1=f1,
                accuracy=acc,
                attack_detected=len(alerts) > 0,
                detected_attack_types=detected_types,
                window_tp=w_tp,
                window_fp=w_fp,
                window_fn=w_fn,
                window_tn=w_tn,
                window_precision=w_prec,
                window_recall=w_rec,
                window_f1=w_f1,
                window_accuracy=w_acc,
            )
        )

    # Scenario-level overall summary
    overall_prec = float(total_tp / (total_tp + total_fp)) if (total_tp + total_fp) > 0 else 0.0
    overall_rec = float(total_tp / (total_tp + total_fn)) if (total_tp + total_fn) > 0 else 0.0
    overall_f1 = (
        float(2 * overall_prec * overall_rec / (overall_prec + overall_rec))
        if (overall_prec + overall_rec) > 0
        else 0.0
    )
    overall_acc = (
        float((total_tp + total_tn) / (total_tp + total_tn + total_fp + total_fn))
        if (total_tp + total_tn + total_fp + total_fn) > 0
        else 0.0
    )

    # Window-level overall summary
    win_prec = float(tot_win_tp / (tot_win_tp + tot_win_fp)) if (tot_win_tp + tot_win_fp) > 0 else 0.0
    win_rec = float(tot_win_tp / (tot_win_tp + tot_win_fn)) if (tot_win_tp + tot_win_fn) > 0 else 0.0
    win_f1 = float(2 * win_prec * win_rec / (win_prec + win_rec)) if (win_prec + win_rec) > 0 else 0.0
    win_acc = (
        float((tot_win_tp + tot_win_tn) / (tot_win_tp + tot_win_tn + tot_win_fp + tot_win_fn))
        if (tot_win_tp + tot_win_tn + tot_win_fp + tot_win_fn) > 0
        else 0.0
    )

    return {
        "mode": mode,
        "scenarios_evaluated": len(scenario_results),
        "total_true_positives": total_tp,
        "total_false_positives": total_fp,
        "total_false_negatives": total_fn,
        "total_true_negatives": total_tn,
        "overall_precision": overall_prec,
        "overall_recall": overall_rec,
        "overall_f1": overall_f1,
        "overall_accuracy": overall_acc,
        "scenario_evaluations": scenario_results,
        "window_metrics": {
            "total_true_positives": tot_win_tp,
            "total_false_positives": tot_win_fp,
            "total_false_negatives": tot_win_fn,
            "total_true_negatives": tot_win_tn,
            "precision": win_prec,
            "recall": win_rec,
            "f1": win_f1,
            "accuracy": win_acc,
        },
    }

