"""Unit and integration tests for SentinelFlow Machine Learning module (sentinelflow/ml.py)."""

from pathlib import Path
from typing import Dict

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

from sentinelflow.ml import (
    FEATURE_COLUMNS,
    IsolationForestAnomalyDetector,
    train_supervised_comparison,
)


@pytest.fixture
def synthetic_benign_df() -> pd.DataFrame:
    """Generate 200 synthetic benign feature window rows with normal distributions."""
    rng = np.random.RandomState(42)
    data = {}
    for col in FEATURE_COLUMNS:
        if "share" in col or "ratio" in col or "fraction" in col:
            data[col] = rng.uniform(0.0, 0.2, size=200)
        elif "count" in col or "pps" in col:
            data[col] = rng.normal(loc=20.0, scale=3.0, size=200).clip(min=1.0)
        else:
            data[col] = rng.normal(loc=50.0, scale=5.0, size=200).clip(min=0.0)
    return pd.DataFrame(data)


def test_pipeline_structure_and_properties(synthetic_benign_df: pd.DataFrame) -> None:
    """Verify that IsolationForestAnomalyDetector constructs a StandardScaler + IsolationForest pipeline."""
    detector = IsolationForestAnomalyDetector(random_state=42, n_estimators=50, target_fpr=0.02)
    assert not detector.is_fitted
    assert detector.pipeline is None
    assert detector.scaler is None
    assert detector.model is None

    detector.fit(synthetic_benign_df)

    assert detector.is_fitted
    assert isinstance(detector.pipeline, Pipeline)
    assert isinstance(detector.scaler, StandardScaler)
    assert isinstance(detector.model, IsolationForest)
    assert detector.threshold != 0.0
    assert detector.s_max > detector.threshold
    assert detector.s_min < detector.threshold
    assert detector.training_mean is not None
    assert detector.training_std is not None
    assert len(detector.training_mean) == len(FEATURE_COLUMNS)


def test_flags_extreme_anomaly_and_not_training_mean(synthetic_benign_df: pd.DataFrame) -> None:
    """Verify that the model flags an obviously extreme synthetic row and does not flag the training mean row."""
    detector = IsolationForestAnomalyDetector(random_state=42, n_estimators=100, target_fpr=0.01)
    detector.fit(synthetic_benign_df)

    # 1. Training Mean Row (should be inlier, not flagged)
    mean_row = detector.training_mean.to_dict()
    mean_score = detector.score(mean_row)
    mean_pred = detector.predict(mean_row)

    assert isinstance(mean_score, float)
    assert 0.0 <= mean_score < 0.5, f"Training mean score {mean_score} should be < 0.5 (benign)"
    assert mean_pred is False, "Training mean should not be flagged as anomalous"

    # Also test passing training mean as pd.Series and single-row DataFrame
    mean_series = pd.Series(mean_row)
    assert detector.score(mean_series) < 0.5
    assert detector.predict(mean_series) is False

    mean_df = pd.DataFrame([mean_row])
    df_scores = detector.score(mean_df)
    df_preds = detector.predict(mean_df)
    assert isinstance(df_scores, np.ndarray)
    assert df_scores[0] < 0.5
    assert bool(df_preds[0]) is False

    # 2. Obviously Extreme Synthetic Row (massive port scan / SYN surge)
    extreme_row = dict(mean_row)
    extreme_row["unique_dst_ports"] = 5000.0
    extreme_row["pps"] = 50000.0
    extreme_row["syn_count"] = 40000.0
    extreme_row["packet_count"] = 250000.0
    extreme_row["bytes_per_sec"] = 50000000.0
    extreme_row["connections_to_same_dst_port_max"] = 1000.0

    extreme_score = detector.score(extreme_row)
    extreme_pred = detector.predict(extreme_row)

    assert isinstance(extreme_score, float)
    assert extreme_score > 0.5, f"Extreme row score {extreme_score} should be > 0.5 (anomalous)"
    assert extreme_pred is True, "Obviously extreme row must be flagged as anomalous"


def test_explain_top_deviating_features(synthetic_benign_df: pd.DataFrame) -> None:
    """Verify that explain() returns top-3 readable strings like 'unique_dst_ports +14.2σ'."""
    detector = IsolationForestAnomalyDetector(random_state=42, n_estimators=50)
    detector.fit(synthetic_benign_df)

    mean_row = detector.training_mean.to_dict()
    extreme_row = dict(mean_row)
    # Spike specific features
    extreme_row["unique_dst_ports"] = float(mean_row["unique_dst_ports"]) + 14.2 * float(detector.training_std["unique_dst_ports"])
    extreme_row["pps"] = float(mean_row["pps"]) + 8.5 * float(detector.training_std["pps"])
    extreme_row["syn_count"] = float(mean_row["syn_count"]) + 5.0 * float(detector.training_std["syn_count"])

    explanations = detector.explain(extreme_row, top_k=3)
    assert isinstance(explanations, list)
    assert len(explanations) == 3

    # Check formatting: feature name + signed deviation + sigma
    assert any("unique_dst_ports" in exp and "+14.2σ" in exp for exp in explanations)
    assert any("pps" in exp and "+8.5σ" in exp for exp in explanations)
    assert any("syn_count" in exp and "+5.0σ" in exp for exp in explanations)

    # Check dictionary explanation
    exp_dict = detector.explain_dict(extreme_row, top_k=3)
    assert isinstance(exp_dict, dict)
    assert len(exp_dict) == 3
    assert "unique_dst_ports" in exp_dict
    assert pytest.approx(exp_dict["unique_dst_ports"], rel=1e-1) == 14.2


def test_save_and_load_joblib(tmp_path: Path, synthetic_benign_df: pd.DataFrame) -> None:
    """Verify saving and loading the trained detector using joblib."""
    detector = IsolationForestAnomalyDetector(random_state=42, n_estimators=50)
    detector.fit(synthetic_benign_df)

    model_file = tmp_path / "models" / "isolation_forest.joblib"
    saved_path = detector.save(model_file)
    assert saved_path.is_file()

    loaded_detector = IsolationForestAnomalyDetector.load(model_file)
    assert loaded_detector.is_fitted
    assert loaded_detector.threshold == detector.threshold
    assert loaded_detector.s_min == detector.s_min
    assert loaded_detector.s_max == detector.s_max

    # Compare predictions
    mean_row = detector.training_mean.to_dict()
    assert loaded_detector.score(mean_row) == pytest.approx(detector.score(mean_row), abs=1e-6)
    assert loaded_detector.predict(mean_row) == detector.predict(mean_row)


def test_target_fpr_threshold_calibration(synthetic_benign_df: pd.DataFrame) -> None:
    """Verify that target_fpr adapts the empirical validation decision threshold."""
    # Stricter FPR (0.01) means 99th percentile threshold, looser FPR (0.10) means 90th percentile
    det_strict = IsolationForestAnomalyDetector(random_state=42, target_fpr=0.01).fit(synthetic_benign_df)
    det_loose = IsolationForestAnomalyDetector(random_state=42, target_fpr=0.10).fit(synthetic_benign_df)

    assert det_strict.threshold >= det_loose.threshold, "Stricter target_fpr must produce a higher decision threshold"


def test_batch_and_empty_inputs(synthetic_benign_df: pd.DataFrame) -> None:
    """Verify batch scoring on DataFrames and safe handling of empty inputs."""
    detector = IsolationForestAnomalyDetector(random_state=42, n_estimators=50).fit(synthetic_benign_df)

    # Batch DataFrame
    scores = detector.score(synthetic_benign_df)
    preds = detector.predict(synthetic_benign_df)
    assert isinstance(scores, np.ndarray)
    assert len(scores) == len(synthetic_benign_df)
    assert np.all((scores >= 0.0) & (scores <= 1.0))
    assert isinstance(preds, np.ndarray)
    assert preds.dtype == bool

    # Empty inputs
    empty_df = pd.DataFrame()
    assert len(detector.score(empty_df)) == 0
    assert len(detector.predict(empty_df)) == 0
