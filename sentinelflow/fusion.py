"""Hybrid Alert Fusion and Arbitration Engine for SentinelFlow.

Combines deterministic rule-based threat violations with unsupervised Isolation Forest
anomaly scores. Arbitrates confidence levels (HIGH, MEDIUM, LOW), calculates calibrated
severity scores (0-100), tags ML-only detections as 'unknown_anomaly', synthesizes
actionable plain-English alert explanations, and exports reports (JSON, CSV, and HTML).
"""

from dataclasses import asdict
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import numpy as np
import pandas as pd
import yaml

from sentinelflow.attack_map import (
    AlertExplanation,
    ConfidenceLevel,
    generate_plain_english_explanation,
    get_mitre_info,
    get_recommendation,
    normalize_rule_key,
)
from sentinelflow.ml import IsolationForestAnomalyDetector
from sentinelflow.rules import Alert

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path("config/default.yaml")


def load_fusion_config(config_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Load fusion hyperparameters from configuration YAML file."""
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    fallback = {
        "weights": {
            "rule_score": 0.6,
            "ml_anomaly_score": 0.4,
        },
        "attack_weights": {
            "port_scan": 1.0,
            "syn_flood": 1.2,
            "udp_flood": 1.1,
            "ssh_bruteforce": 1.1,
            "arp_spoofing": 1.2,
            "unknown_anomaly": 0.9,
        },
        "ml_high_confidence_threshold": 0.80,
    }

    if not path.is_file():
        return fallback

    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        fusion_cfg = cfg.get("fusion", {})
        merged = dict(fallback)
        if "weights" in fusion_cfg:
            merged["weights"].update(fusion_cfg["weights"])
        if "attack_weights" in fusion_cfg:
            merged["attack_weights"].update(fusion_cfg["attack_weights"])
        if "ml_high_confidence_threshold" in fusion_cfg:
            merged["ml_high_confidence_threshold"] = fusion_cfg["ml_high_confidence_threshold"]
        return merged
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not read fusion config from %s: %s; using defaults.", path, exc)
        return fallback


def fuse_detections(
    rule_alerts: List[Alert],
    windows_df: pd.DataFrame,
    ml_detector: Optional[IsolationForestAnomalyDetector] = None,
    config: Optional[Dict[str, Any]] = None,
    packets_df: Optional[pd.DataFrame] = None,
) -> List[AlertExplanation]:
    """Fuse rule-based alerts and unsupervised ML anomaly scores into explainable alerts.

    Arbitration & Severity Rules:
    1. Agreement (Rule triggered + ML anomaly score >= 0.50):
       - Confidence: HIGH
       - Severity: Weighted combination of rule strength and ML anomaly score, scaled by attack-type weight.
    2. Rule Only (Rule triggered, ML score < 0.50 or ML unavailable):
       - Confidence: MEDIUM
       - Severity: Driven by rule severity and margin strength.
    3. ML Only (No rule triggered, ML score >= 0.50):
       - Labeled as 'unknown anomaly' (MITRE T1205).
       - Confidence: MEDIUM if ML score >= 0.80 ('very high ML only'), LOW if 0.50 <= ML < 0.80 ('marginal ML only').
       - Severity: Derived from ML anomaly score scaled by unknown_anomaly weight.

    Args:
        rule_alerts: Consolidated Alert objects from sentinelflow.rules.
        windows_df: DataFrame of extracted per-source window features.
        ml_detector: Optional fitted IsolationForestAnomalyDetector.
        config: Optional configuration dictionary.
        packets_df: Optional parsed raw packet DataFrame.

    Returns:
        List of final unified AlertExplanation records.
    """
    cfg = config if config is not None else load_fusion_config()
    weights = cfg.get("weights", {"rule_score": 0.6, "ml_anomaly_score": 0.4})
    attack_weights = cfg.get(
        "attack_weights",
        {
            "port_scan": 1.0,
            "syn_flood": 1.2,
            "udp_flood": 1.1,
            "ssh_bruteforce": 1.1,
            "arp_spoofing": 1.2,
            "unknown_anomaly": 0.9,
        },
    )
    high_ml_thresh = float(cfg.get("ml_high_confidence_threshold", 0.80))
    w_rule = float(weights.get("rule_score", 0.6))
    w_ml = float(weights.get("ml_anomaly_score", 0.4))

    # Precompute ML anomaly scores across all windows if ML detector is available
    window_scores: np.ndarray = np.empty(0, dtype=np.float64)
    has_ml = ml_detector is not None and getattr(ml_detector, "is_fitted", False) and not windows_df.empty
    if has_ml and ml_detector is not None:
        window_scores = np.asarray(ml_detector.score(windows_df), dtype=np.float64)

    final_alerts: List[AlertExplanation] = []
    covered_window_indices: Set[int] = set()

    # -------------------------------------------------------------------------
    # 1. Process Rule-Based Alerts (correlating with ML window scores)
    # -------------------------------------------------------------------------
    for alert in rule_alerts:
        matched_window_indices: List[int] = []
        alert_ml_score = float(alert.strength)  # default fallback
        top_deviations: Dict[str, float] = {}

        if has_ml and ml_detector is not None and len(window_scores) == len(windows_df):
            # Find windows matching this alert's source IP and time span
            mask = (
                (windows_df["src_ip"] == alert.src_ip)
                & (windows_df["win_end"] >= alert.window_start - 1.0)
                & (windows_df["win_start"] <= alert.window_end + 1.0)
            )
            matched_indices = windows_df.index[mask].tolist()
            matched_window_indices.extend(matched_indices)

            if matched_indices:
                sub_scores = window_scores[matched_indices]
                max_idx = matched_indices[int(np.argmax(sub_scores))]
                alert_ml_score = float(np.max(sub_scores))
                # Top deviating features from peak window
                top_deviations = ml_detector.explain_dict(windows_df.loc[max_idx], top_k=5)

        covered_window_indices.update(matched_window_indices)

        # Confidence Arbitration
        if has_ml and alert_ml_score >= 0.50:
            confidence = ConfidenceLevel.HIGH  # Rule + ML agree
        else:
            confidence = ConfidenceLevel.MEDIUM  # Rule only

        # Severity Calculation
        canonical_attack = normalize_rule_key(alert.rule_id)
        att_weight = float(attack_weights.get(canonical_attack, 1.0))

        rule_val = (alert.severity / 100.0) * (0.8 + 0.2 * alert.strength)
        if has_ml and alert_ml_score > 0.0:
            combined = (w_rule * rule_val + w_ml * alert_ml_score) / (w_rule + w_ml)
            calc_severity = int(np.clip(combined * 100.0 * att_weight, 20, 100))
        else:
            calc_severity = int(np.clip(alert.severity * att_weight, 20, 100))

        # Plain-English Explanation
        duration = max(0.0, alert.window_end - alert.window_start)
        rec = get_recommendation(canonical_attack)
        mitre_info = get_mitre_info(canonical_attack)

        summary = generate_plain_english_explanation(
            detector_name=alert.detector_name or mitre_info["technique_name"],
            technique_id=alert.mitre_technique_id or mitre_info["technique_id"],
            severity=calc_severity,
            confidence=confidence,
            source_ip=alert.src_ip,
            target_ip=alert.dst_ip,
            duration=duration,
            merged_windows_count=alert.merged_windows_count,
            matched_conditions=alert.matched_conditions,
            observed_values=alert.observed,
            thresholds=alert.thresholds,
            top_deviating_features=top_deviations,
            recommendation=rec,
        )

        final_alerts.append(
            AlertExplanation(
                rule_id=alert.rule_id,
                detector_name=alert.detector_name or mitre_info["technique_name"],
                matched_conditions=alert.matched_conditions,
                observed_values=alert.observed,
                thresholds=alert.thresholds,
                anomaly_score=alert_ml_score if has_ml else alert.strength,
                top_deviating_features=top_deviations,
                severity=calc_severity,
                confidence=confidence,
                mitre_technique_id=alert.mitre_technique_id or mitre_info["technique_id"],
                mitre_technique_name=alert.mitre_technique_name or mitre_info["technique_name"],
                mitre_tactic=alert.mitre_tactic or mitre_info["tactic"],
                source_ip=alert.src_ip,
                target_ip=alert.dst_ip,
                timestamp=alert.window_start,
                window_end=alert.window_end,
                duration=duration,
                merged_windows_count=alert.merged_windows_count,
                recommendation=rec,
                summary=summary,
            )
        )

    # -------------------------------------------------------------------------
    # 2. Process ML-Only Detections ('unknown_anomaly')
    # -------------------------------------------------------------------------
    if has_ml and ml_detector is not None and len(window_scores) == len(windows_df):
        # Identify anomalous windows not covered by any rule alert
        uncovered_mask = ~windows_df.index.isin(covered_window_indices)
        ml_anom_mask = (window_scores >= 0.50) & uncovered_mask

        anom_indices = windows_df.index[ml_anom_mask].tolist()
        if anom_indices:
            anom_df = windows_df.loc[anom_indices].copy()
            anom_df["ml_score"] = window_scores[anom_indices]

            # Merge adjacent anomalous windows for the same source IP
            merged_clusters = _merge_ml_anomalous_windows(anom_df, max_gap=5.0)

            for cluster in merged_clusters:
                peak_score = float(cluster["peak_score"])
                # Confidence: MEDIUM if very high ML score, LOW if marginal ML
                if peak_score >= high_ml_thresh:
                    conf = ConfidenceLevel.MEDIUM
                else:
                    conf = ConfidenceLevel.LOW

                att_weight = float(attack_weights.get("unknown_anomaly", 0.9))
                calc_sev = int(np.clip(peak_score * 100.0 * att_weight, 15, 95))

                mitre_info = get_mitre_info("unknown_anomaly")
                rec = get_recommendation("unknown_anomaly")

                # Top deviating features from peak window row
                peak_row = cluster["peak_row"]
                top_deviations = ml_detector.explain_dict(peak_row, top_k=5)

                duration = max(0.0, cluster["win_end"] - cluster["win_start"])
                summary = generate_plain_english_explanation(
                    detector_name="Isolation Forest Anomaly Detector",
                    technique_id=mitre_info["technique_id"],
                    severity=calc_sev,
                    confidence=conf,
                    source_ip=cluster["src_ip"],
                    target_ip=cluster.get("dst_ip"),
                    duration=duration,
                    merged_windows_count=cluster["window_count"],
                    matched_conditions=[
                        f"Unsupervised Isolation Forest detected statistical traffic anomaly (score: {peak_score:.2f} >= 0.50)"
                    ],
                    observed_values={
                        "anomaly_score": peak_score,
                        "pps": float(peak_row.get("pps", 0.0)),
                        "unique_dst_ports": int(peak_row.get("unique_dst_ports", 0)),
                        "bytes_per_sec": float(peak_row.get("bytes_per_sec", 0.0)),
                    },
                    thresholds={"anomaly_threshold": 0.50},
                    top_deviating_features=top_deviations,
                    recommendation=rec,
                )

                final_alerts.append(
                    AlertExplanation(
                        rule_id="ML-IFOREST-ANOMALY",
                        detector_name="Isolation Forest Anomaly Detector",
                        matched_conditions=[
                            f"Unsupervised Isolation Forest detected statistical traffic anomaly (score: {peak_score:.2f} >= 0.50)"
                        ],
                        observed_values={
                            "anomaly_score": peak_score,
                            "pps": float(peak_row.get("pps", 0.0)),
                            "unique_dst_ports": int(peak_row.get("unique_dst_ports", 0)),
                            "bytes_per_sec": float(peak_row.get("bytes_per_sec", 0.0)),
                        },
                        thresholds={"anomaly_threshold": 0.50},
                        anomaly_score=peak_score,
                        top_deviating_features=top_deviations,
                        severity=calc_sev,
                        confidence=conf,
                        mitre_technique_id=mitre_info["technique_id"],
                        mitre_technique_name=mitre_info["technique_name"],
                        mitre_tactic=mitre_info["tactic"],
                        source_ip=cluster["src_ip"],
                        target_ip=cluster.get("dst_ip"),
                        timestamp=cluster["win_start"],
                        window_end=cluster["win_end"],
                        duration=duration,
                        merged_windows_count=cluster["window_count"],
                        recommendation=rec,
                        summary=summary,
                    )
                )

    # Sort final unified alerts chronologically
    final_alerts.sort(key=lambda a: (a.timestamp or 0.0, a.source_ip or ""))
    return final_alerts


def _merge_ml_anomalous_windows(anom_df: pd.DataFrame, max_gap: float = 5.0) -> List[Dict[str, Any]]:
    """Merge adjacent anomalous window rows for the same source IP into single events."""
    clusters: List[Dict[str, Any]] = []

    for src_ip, group in anom_df.groupby("src_ip"):
        sorted_rows = group.sort_values("win_start")
        current_cluster: List[pd.Series] = []

        for _, row in sorted_rows.iterrows():
            if not current_cluster:
                current_cluster.append(row)
                continue

            last_row = current_cluster[-1]
            if float(row["win_start"]) <= float(last_row["win_end"]) + max_gap:
                current_cluster.append(row)
            else:
                clusters.append(_consolidate_ml_cluster(str(src_ip), current_cluster))
                current_cluster = [row]

        if current_cluster:
            clusters.append(_consolidate_ml_cluster(str(src_ip), current_cluster))

    return clusters


def _consolidate_ml_cluster(src_ip: str, cluster: List[pd.Series]) -> Dict[str, Any]:
    """Consolidate a cluster of contiguous ML anomalous window rows."""
    win_start = min(float(r["win_start"]) for r in cluster)
    win_end = max(float(r["win_end"]) for r in cluster)
    scores = [float(r["ml_score"]) for r in cluster]
    max_idx = int(np.argmax(scores))
    peak_score = scores[max_idx]
    peak_row = cluster[max_idx].to_dict()

    return {
        "src_ip": src_ip,
        "win_start": win_start,
        "win_end": win_end,
        "window_count": len(cluster),
        "peak_score": peak_score,
        "peak_row": peak_row,
    }


# =============================================================================
# Alert Exporters: JSON, CSV, and HTML Incident Report
# =============================================================================


def export_alerts_json(alerts: List[AlertExplanation], out_path: Union[str, Path]) -> Path:
    """Export alerts list to formatted JSON file."""
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = [alert.to_dict() for alert in alerts]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    logger.info("Exported %d alerts to JSON: %s", len(alerts), path)
    return path


def export_alerts_csv(alerts: List[AlertExplanation], out_path: Union[str, Path]) -> Path:
    """Export alerts list to CSV spreadsheet."""
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for a in alerts:
        rows.append(
            {
                "rule_id": a.rule_id,
                "detector_name": a.detector_name,
                "source_ip": a.source_ip,
                "target_ip": a.target_ip or "",
                "window_start": a.timestamp,
                "window_end": a.window_end,
                "duration_seconds": round(a.duration, 2),
                "merged_windows": a.merged_windows_count,
                "severity": a.severity,
                "confidence": a.confidence.value if isinstance(a.confidence, ConfidenceLevel) else str(a.confidence),
                "mitre_technique_id": a.mitre_technique_id,
                "mitre_technique_name": a.mitre_technique_name,
                "mitre_tactic": a.mitre_tactic,
                "anomaly_score": round(a.anomaly_score, 4),
                "recommendation": a.recommendation,
                "summary": a.summary,
            }
        )

    df = pd.DataFrame(rows)
    df.to_csv(path, index=False, encoding="utf-8")
    logger.info("Exported %d alerts to CSV: %s", len(alerts), path)
    return path


def export_incident_report_html(
    alerts: List[AlertExplanation],
    out_path: Union[str, Path],
    pcap_name: str = "",
) -> Path:
    """Export a comprehensive, professional HTML security incident report.

    Features:
    - Executive summary KPI metric cards.
    - Interactive sortable incident overview table with color-coded severity badges.
    - One detailed section per incident with observed metrics vs thresholds and MITRE details.
    - Actionable analyst recommendations.
    - Clean, modern cybersecurity dark-mode design system with responsive typography.
    """
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    total_alerts = len(alerts)
    high_count = sum(1 for a in alerts if a.severity >= 80)
    med_count = sum(1 for a in alerts if 50 <= a.severity < 80)
    low_count = sum(1 for a in alerts if a.severity < 50)
    unique_sources = len({a.source_ip for a in alerts if a.source_ip})
    unique_techniques = len({a.mitre_technique_id for a in alerts if a.mitre_technique_id})
    peak_severity = max((a.severity for a in alerts), default=0)

    # Generate table rows
    table_rows_html = []
    sections_html = []

    for i, a in enumerate(alerts, 1):
        # Color coding for severity
        if a.severity >= 80:
            sev_badge = f'<span class="badge badge-high">{a.severity} HIGH</span>'
            card_border = "border-high"
        elif a.severity >= 50:
            sev_badge = f'<span class="badge badge-med">{a.severity} MED</span>'
            card_border = "border-med"
        else:
            sev_badge = f'<span class="badge badge-low">{a.severity} LOW</span>'
            card_border = "border-low"

        conf_str = a.confidence.value if isinstance(a.confidence, ConfidenceLevel) else str(a.confidence)
        conf_badge = f'<span class="badge badge-conf-{conf_str.lower()}">{conf_str}</span>'

        target = a.target_ip or "—"
        dur = f"{a.duration:.1f}s" if a.duration > 0 else "—"

        table_rows_html.append(
            f"""
            <tr>
                <td><strong>#{i}</strong></td>
                <td>{sev_badge}</td>
                <td>{conf_badge}</td>
                <td><code>{a.mitre_technique_id}</code></td>
                <td>{a.detector_name}</td>
                <td><code>{a.source_ip or '—'}</code></td>
                <td><code>{target}</code></td>
                <td>{dur}</td>
                <td><a href="#incident-{i}" class="btn-link">View Event</a></td>
            </tr>
            """
        )

        # Build Observed Values Table
        obs_rows = []
        for k, v in a.observed_values.items():
            thresh_val = a.thresholds.get(k, "—")
            val_str = f"{v:.2f}" if isinstance(v, float) else str(v)
            th_str = f"{thresh_val:.2f}" if isinstance(thresh_val, float) else str(thresh_val)
            obs_rows.append(f"<tr><td><code>{k}</code></td><td><strong>{val_str}</strong></td><td>{th_str}</td></tr>")

        obs_table_html = "".join(obs_rows) if obs_rows else "<tr><td colspan='3'>No raw metrics recorded</td></tr>"

        # Baseline deviations badges
        dev_badges = []
        for feat, z in a.top_deviating_features.items():
            sign = f"+{z:.1f}σ" if z >= 0 else f"{z:.1f}σ"
            dev_badges.append(f'<span class="feat-pill">{feat} <strong>{sign}</strong></span>')
        dev_html = " ".join(dev_badges) if dev_badges else "<em>None recorded</em>"

        # Conditions list
        cond_items = "".join(f"<li>{c}</li>" for c in a.matched_conditions)

        sections_html.append(
            f"""
            <div class="incident-card {card_border}" id="incident-{i}">
                <div class="card-header">
                    <div class="card-title-group">
                        <span class="incident-num">Incident #{i}</span>
                        <h3>{a.detector_name}</h3>
                        <span class="mitre-tag">{a.mitre_technique_id}: {a.mitre_technique_name} ({a.mitre_tactic})</span>
                    </div>
                    <div class="card-badges">
                        {sev_badge}
                        {conf_badge}
                    </div>
                </div>

                <div class="incident-summary-box">
                    <p class="summary-text">{a.summary}</p>
                </div>

                <div class="incident-details-grid">
                    <div class="detail-col">
                        <h4>Endpoint Attributes</h4>
                        <table class="mini-table">
                            <tr><td>Source IP</td><td><code>{a.source_ip or '—'}</code></td></tr>
                            <tr><td>Target IP</td><td><code>{a.target_ip or '—'}</code></td></tr>
                            <tr><td>Duration</td><td>{a.duration:.1f}s ({a.merged_windows_count} window{'s' if a.merged_windows_count != 1 else ''})</td></tr>
                            <tr><td>ML Anomaly Score</td><td><strong>{a.anomaly_score:.4f}</strong></td></tr>
                        </table>

                        <h4>Matched Conditions</h4>
                        <ul class="cond-list">
                            {cond_items}
                        </ul>
                    </div>

                    <div class="detail-col">
                        <h4>Observed Metrics vs Thresholds</h4>
                        <table class="mini-table">
                            <thead>
                                <tr><th>Metric</th><th>Observed</th><th>Threshold</th></tr>
                            </thead>
                            <tbody>
                                {obs_table_html}
                            </tbody>
                        </table>

                        <h4>Top Baseline Deviations (z-score)</h4>
                        <div class="feat-container">
                            {dev_html}
                        </div>
                    </div>
                </div>

                <div class="rec-box">
                    <strong>Analyst Recommendation:</strong> {a.recommendation}
                </div>
            </div>
            """
        )

    table_content = "\n".join(table_rows_html) if table_rows_html else "<tr><td colspan='9'>No intrusion incidents detected.</td></tr>"
    sections_content = "\n".join(sections_html) if sections_html else "<div class='empty-state'>All traffic conformed to normal baseline behavior. Zero threat detections.</div>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelFlow Security Incident Report</title>
    <style>
        :root {{
            --bg-dark: #0b0f19;
            --surface: #111827;
            --surface-card: #1e293b;
            --surface-border: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-blue: #38bdf8;
            --accent-red: #ef4444;
            --accent-amber: #f59e0b;
            --accent-green: #10b981;
            --accent-cyan: #06b6d4;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            line-height: 1.5;
            padding: 2rem 1.5rem;
        }}
        .container {{ max-width: 1280px; margin: 0 auto; }}
        header {{
            margin-bottom: 2rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--surface-border);
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        .logo-title h1 {{ font-size: 2rem; font-weight: 800; color: #fff; letter-spacing: -0.5px; }}
        .logo-title p {{ color: var(--text-muted); font-size: 0.95rem; }}
        .header-meta {{ text-align: right; font-size: 0.9rem; color: var(--text-muted); }}

        /* KPI Cards */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2.5rem;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 8px;
            padding: 1.25rem;
        }}
        .kpi-card .kpi-label {{ font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }}
        .kpi-card .kpi-val {{ font-size: 2rem; font-weight: 800; margin-top: 0.25rem; }}
        .val-red {{ color: var(--accent-red); }}
        .val-amber {{ color: var(--accent-amber); }}
        .val-blue {{ color: var(--accent-blue); }}
        .val-green {{ color: var(--accent-green); }}

        /* Table */
        .section-title {{ font-size: 1.4rem; font-weight: 700; margin-bottom: 1rem; }}
        .table-wrap {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 8px;
            overflow-x: auto;
            margin-bottom: 3rem;
        }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }}
        th, td {{ padding: 0.75rem 1rem; border-bottom: 1px solid var(--surface-border); }}
        th {{ background: #0f172a; color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; }}
        tr:hover td {{ background: rgba(255, 255, 255, 0.02); }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.55rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.3px;
        }}
        .badge-high {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-med {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
        .badge-low {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); }}
        .badge-conf-high {{ background: #064e3b; color: #34d399; }}
        .badge-conf-medium {{ background: #78350f; color: #fde68a; }}
        .badge-conf-low {{ background: #1e293b; color: #94a3b8; }}
        .mitre-tag {{ background: #1e1b4b; color: #a5b4fc; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }}
        .btn-link {{ color: var(--accent-blue); text-decoration: none; font-weight: 600; }}
        .btn-link:hover {{ text-decoration: underline; }}
        code {{ background: rgba(0,0,0,0.3); padding: 0.15rem 0.4rem; border-radius: 3px; font-family: monospace; font-size: 0.85rem; color: #e2e8f0; }}

        /* Incident Section Cards */
        .incident-card {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        .border-high {{ border-left: 5px solid var(--accent-red); }}
        .border-med {{ border-left: 5px solid var(--accent-amber); }}
        .border-low {{ border-left: 5px solid var(--accent-cyan); }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1rem;
        }}
        .incident-num {{ font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700; }}
        .card-title-group h3 {{ font-size: 1.3rem; margin: 0.2rem 0 0.4rem; color: #fff; }}
        .card-badges {{ display: flex; gap: 0.5rem; align-items: center; }}
        .incident-summary-box {{
            background: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 1.25rem;
        }}
        .summary-text {{ font-size: 0.95rem; color: #e2e8f0; }}
        .incident-details-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 1.25rem;
        }}
        @media (max-width: 800px) {{ .incident-details-grid {{ grid-template-columns: 1fr; }} }}
        .detail-col h4 {{ font-size: 0.85rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.5rem; letter-spacing: 0.5px; }}
        .mini-table {{ margin-bottom: 1rem; width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
        .mini-table td, .mini-table th {{ padding: 0.4rem 0.6rem; border-bottom: 1px solid #1e293b; }}
        .cond-list {{ padding-left: 1.2rem; font-size: 0.85rem; color: #cbd5e1; }}
        .cond-list li {{ margin-bottom: 0.3rem; }}
        .feat-container {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
        .feat-pill {{ background: #1e293b; border: 1px solid #334155; padding: 0.3rem 0.6rem; border-radius: 4px; font-size: 0.8rem; color: #cbd5e1; }}
        .rec-box {{
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: 6px;
            padding: 0.75rem 1rem;
            font-size: 0.9rem;
            color: #d1fae5;
        }}
        .empty-state {{ padding: 3rem; text-align: center; color: var(--text-muted); font-size: 1.1rem; background: var(--surface); border-radius: 8px; border: 1px solid var(--surface-border); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-title">
                <h1>SentinelFlow Incident Report</h1>
                <p>Explainable Hybrid Network Intrusion Detection Analysis</p>
            </div>
            <div class="header-meta">
                <div>Source Capture: <code>{pcap_name or 'pcap_stream'}</code></div>
                <div>Generated: Standard Epoch</div>
            </div>
        </header>

        <!-- KPI Metric Cards -->
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">Total Incidents</div>
                <div class="kpi-val val-blue">{total_alerts}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">High Severity (80+)</div>
                <div class="kpi-val val-red">{high_count}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Medium Severity (50-79)</div>
                <div class="kpi-val val-amber">{med_count}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Attacking Sources</div>
                <div class="kpi-val val-blue">{unique_sources}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">ATT&CK Techniques</div>
                <div class="kpi-val val-green">{unique_techniques}</div>
            </div>
        </div>

        <!-- Incident Summary Table -->
        <h2 class="section-title">Detected Incident Overview</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Severity</th>
                        <th>Confidence</th>
                        <th>Technique</th>
                        <th>Detector Name</th>
                        <th>Attacker IP</th>
                        <th>Target IP</th>
                        <th>Duration</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {table_content}
                </tbody>
            </table>
        </div>

        <!-- Detailed Event Breakdown -->
        <h2 class="section-title">Incident Analysis & Evidence</h2>
        {sections_content}
    </div>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info("Exported HTML incident report to: %s", path)
    return path
