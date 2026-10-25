"""Machine Learning Anomaly Detection Module for SentinelFlow.

Trains and evaluates an unsupervised Isolation Forest anomaly detector trained EXCLUSIVELY
on benign baseline network traffic.

Architectural Design & Decision Threshold Selection Rationale:
--------------------------------------------------------------
1. StandardScaler + IsolationForest Pipeline:
   Input features exhibit vastly different scales (e.g. PPS reaching thousands while protocol
   shares reside in [0.0, 1.0]). A scikit-learn Pipeline chaining StandardScaler and IsolationForest
   ensures feature dimensions are standardized (zero mean, unit variance) so random hyperplanes
   in the ensemble partition feature space isotropically without being dominated by high-magnitude scales.

2. Empirical Validation-Split Decision Threshold (Why NOT default contamination):
   Scikit-learn's IsolationForest provides a `contamination` parameter which defaults to 'auto' or
   requires a float representing the expected proportion of outliers in the data.
   Crucially, when training strictly on benign baseline network traffic, the expected contamination
   is ZERO. Setting an arbitrary contamination (e.g. 0.05 or 0.10) forces the algorithm to artificially
   label 5% or 10% of legitimate baseline enterprise traffic as anomalous, inducing severe alert fatigue.
   Instead, SentinelFlow fits the Isolation Forest with `contamination="auto"` and reserves a held-out
   benign validation split (default: 20%). The decision threshold is chosen empirically as the
   (1 - target_fpr) quantile of raw outlier scores on the benign validation set (default: 99th percentile
   targeting a 1% false positive rate). This guarantees a mathematically bounded operational false-alarm
   rate on unseen benign traffic.

3. Calibrated Normalised Anomaly Scoring (0.0 to 1.0):
   Raw decision scores s_raw = -decision_function(x) are mapped to a calibrated [0.0, 1.0] range
   anchored at the empirical threshold:
   - score < 0.5: Inlier (benign traffic, with training mean residing near ~0.0 - 0.2).
   - score == 0.5: Exact calibrated operational decision boundary.
   - score > 0.5: Anomalous threat, scaling smoothly up to 1.0 for severe deviations.

4. Actionable Explainability Attribution:
   For any detected anomalous window, feature-level z-scores are computed against benign baseline
   statistics: z = (observed - mu_benign) / max(sigma_benign, 1.0).
   The top deviating features are ranked and formatted as human-readable strings, e.g.:
   "unique_dst_ports +14.2σ", giving SOC analysts instant context into why the window was flagged.

5. Optional Supervised Comparison Model:
   An optional RandomForestClassifier trained on labelled windows from training PCAPs and evaluated
   on holdout PCAPs, selectable via the `--supervised` flag for academic benchmarking.
"""

from dataclasses import dataclass
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
import typer

from sentinelflow.features import extract_window_features, label_windows
from sentinelflow.parser import parse_pcap

logger = logging.getLogger(__name__)

DEFAULT_MODEL_DIR = Path("models")
DEFAULT_MODEL_PATH = DEFAULT_MODEL_DIR / "isolation_forest.joblib"
DEFAULT_BENIGN_PCAP = Path("data/pcaps/s1_benign.pcap")

# Canonical numerical feature columns used for ML modeling
FEATURE_COLUMNS: List[str] = [
    "packet_count",
    "pps",
    "bps",
    "bytes_per_sec",
    "unique_dst_ips",
    "unique_dst_ports",
    "syn_count",
    "synack_ratio",
    "syn_without_ack_fraction",
    "short_connection_fraction",
    "connections_to_same_dst_port_max",
    "mean_packet_size",
    "std_packet_size",
    "tcp_share",
    "udp_share",
    "icmp_share",
    "arp_share",
    "inter_arrival_mean",
    "inter_arrival_std",
    "arp_reply_count",
    "mac_binding_changes",
]


class IsolationForestAnomalyDetector:
    """Unsupervised Isolation Forest anomaly detector trained strictly on benign baseline traffic.

    Chains StandardScaler + IsolationForest in a pipeline, calibrates the operational threshold
    on a benign validation split targeting a configurable false-positive rate, and provides
    normalized scoring and z-score explainability.
    """

    def __init__(
        self,
        random_state: int = 42,
        n_estimators: int = 100,
        target_fpr: float = 0.01,
        feature_columns: Optional[List[str]] = None,
    ) -> None:
        """Initialize the anomaly detector.

        Args:
            random_state: Fixed random seed for deterministic tree construction.
            n_estimators: Number of isolation trees in the ensemble.
            target_fpr: Target false positive rate for empirical threshold calibration (default: 0.01).
            feature_columns: Specific feature column names (defaults to FEATURE_COLUMNS).
        """
        self.random_state = random_state
        self.n_estimators = n_estimators
        self.target_fpr = target_fpr
        self.feature_columns = list(feature_columns or FEATURE_COLUMNS)

        self.pipeline: Optional[Pipeline] = None
        self.threshold: float = 0.0
        self.s_min: float = -0.5
        self.s_max: float = 0.5
        self.training_mean: Optional[pd.Series] = None
        self.training_std: Optional[pd.Series] = None
        self.is_fitted: bool = False

    @property
    def scaler(self) -> Optional[StandardScaler]:
        """Access the fitted StandardScaler step of the pipeline."""
        if self.pipeline is not None and "scaler" in self.pipeline.named_steps:
            return self.pipeline.named_steps["scaler"]
        return None

    @property
    def model(self) -> Optional[IsolationForest]:
        """Access the fitted IsolationForest step of the pipeline."""
        if self.pipeline is not None and "model" in self.pipeline.named_steps:
            return self.pipeline.named_steps["model"]
        return None

    def _prepare_features(self, df: Union[pd.DataFrame, pd.Series, dict]) -> np.ndarray:
        """Extract and align feature columns, imputing missing values with 0.0."""
        if isinstance(df, dict):
            df_in = pd.DataFrame([df])
        elif isinstance(df, pd.Series):
            df_in = pd.DataFrame([df])
        else:
            df_in = df

        if df_in.empty:
            return np.empty((0, len(self.feature_columns)), dtype=np.float64)

        aligned = pd.DataFrame(index=df_in.index)
        for col in self.feature_columns:
            if col in df_in.columns:
                aligned[col] = pd.to_numeric(df_in[col], errors="coerce").fillna(0.0)
            else:
                aligned[col] = 0.0

        return aligned[self.feature_columns].values.astype(np.float64)

    def fit(
        self,
        benign_windows_df: pd.DataFrame,
        target_fpr: Optional[float] = None,
        val_size: float = 0.2,
    ) -> "IsolationForestAnomalyDetector":
        """Fit StandardScaler + IsolationForest pipeline strictly on benign baseline traffic.

        Decision Threshold Selection Rationale:
        Instead of using scikit-learn's default `contamination` parameter (which arbitrarily
        assumes malicious contamination in the training dataset itself), we train on clean benign
        data with `contamination="auto"`. We then evaluate raw decision scores on a held-out benign
        validation split (20%) and choose the operational decision threshold at the empirical
        (1 - target_fpr) quantile (e.g. 99th percentile for target_fpr=0.01).
        This guarantees an empirical upper bound on the false-positive rate for operational NIDS deployment.

        Args:
            benign_windows_df: DataFrame of window features extracted from benign baseline traffic.
            target_fpr: Desired operational false-positive rate (defaults to self.target_fpr).
            val_size: Fraction of benign samples reserved for empirical threshold calibration (default: 0.2).

        Returns:
            Fitted instance of IsolationForestAnomalyDetector.
        """
        if benign_windows_df.empty:
            raise ValueError("Cannot train IsolationForest on empty DataFrame.")

        if target_fpr is not None:
            self.target_fpr = target_fpr

        X_all = self._prepare_features(benign_windows_df)
        df_feat = pd.DataFrame(X_all, columns=self.feature_columns)

        # Baseline mean and std for z-score explainability attribution
        self.training_mean = df_feat.mean()
        raw_std = df_feat.std(ddof=0)
        # Avoid division by zero or astronomical z-scores when a feature was constant in baseline
        self.training_std = raw_std.apply(lambda s: float(s) if s > 1e-4 else 1.0)

        # Train / Validation Split on benign baseline
        if len(X_all) >= 10:
            X_train, X_val = train_test_split(
                X_all,
                test_size=val_size,
                random_state=self.random_state,
                shuffle=True,
            )
        else:
            X_train = X_all
            X_val = X_all

        # Construct and fit StandardScaler + IsolationForest pipeline
        self.pipeline = Pipeline([
            ("scaler", StandardScaler()),
            (
                "model",
                IsolationForest(
                    n_estimators=self.n_estimators,
                    max_samples="auto",
                    contamination="auto",
                    random_state=self.random_state,
                    n_jobs=-1,
                ),
            ),
        ])
        self.pipeline.fit(X_train)

        # Decision threshold calibration on benign validation split
        # Raw anomaly score: s_raw = -decision_function(x) (higher = more anomalous)
        val_scores_raw = -self.pipeline.decision_function(X_val)

        q = float(np.clip(1.0 - self.target_fpr, 0.50, 0.999))
        self.threshold = float(np.quantile(val_scores_raw, q))

        # Dynamic range anchors for [0.0, 1.0] score normalization
        self.s_min = float(np.min(val_scores_raw))
        self.s_max = max(self.threshold + 0.15, 0.45)

        self.is_fitted = True
        logger.info(
            "Fitted IsolationForest on %d benign windows (val=%d). Calibrated threshold=%.4f (target_fpr=%.2f%%)",
            len(X_train),
            len(X_val),
            self.threshold,
            self.target_fpr * 100.0,
        )
        return self

    def score(
        self,
        windows: Union[pd.DataFrame, pd.Series, dict, np.ndarray],
    ) -> Union[float, np.ndarray]:
        """Compute normalized anomaly score in range [0.0, 1.0] (higher = more anomalous).

        Score Normalization Rationale:
        Anchors the calibrated decision threshold exactly at 0.5:
        - score < 0.5: Classified as benign inlier.
        - score == 0.5: Operational decision threshold.
        - score > 0.5: Classified as anomalous threat, scaling smoothly to 1.0.

        Args:
            windows: Input window features (DataFrame, Series, dict, or 2D array).

        Returns:
            Float score for single-row inputs (Series or dict), or 1D NumPy array for batch inputs.
        """
        if not self.is_fitted or self.pipeline is None:
            raise RuntimeError("IsolationForestAnomalyDetector must be fitted before calling score().")

        is_single = isinstance(windows, (pd.Series, dict))
        if isinstance(windows, np.ndarray):
            X = windows.reshape(1, -1) if windows.ndim == 1 else windows
        else:
            X = self._prepare_features(windows)

        if len(X) == 0:
            return np.empty(0, dtype=np.float64)

        # In scikit-learn, decision_function returns positive for inliers, negative for outliers
        raw_scores = -self.pipeline.decision_function(X)

        # Calibrated piecewise mapping anchoring threshold at 0.50
        normalized = np.zeros_like(raw_scores, dtype=np.float64)
        below_thresh = raw_scores < self.threshold
        above_thresh = ~below_thresh

        # Below threshold: map [s_min, threshold) -> [0.0, 0.5)
        denom_below = max(1e-4, self.threshold - self.s_min)
        normalized[below_thresh] = 0.5 * np.clip(
            (raw_scores[below_thresh] - self.s_min) / denom_below, 0.0, 1.0
        )

        # Above threshold: map [threshold, s_max] -> [0.5, 1.0]
        denom_above = max(1e-4, self.s_max - self.threshold)
        normalized[above_thresh] = 0.5 + 0.5 * np.clip(
            (raw_scores[above_thresh] - self.threshold) / denom_above, 0.0, 1.0
        )

        if is_single or (isinstance(windows, np.ndarray) and windows.ndim == 1):
            return float(normalized[0])
        return normalized

    def predict(
        self,
        windows: Union[pd.DataFrame, pd.Series, dict, np.ndarray],
    ) -> Union[bool, np.ndarray]:
        """Predict whether windows are anomalous based on the calibrated threshold.

        Args:
            windows: Input window features.

        Returns:
            Boolean for single-row inputs, or boolean array for batch inputs (True = anomalous).
        """
        scores = self.score(windows)
        if isinstance(scores, (float, int, np.floating)):
            return bool(scores >= 0.5)
        return scores >= 0.5

    def explain(
        self,
        window_row: Union[pd.Series, dict, pd.DataFrame],
        top_k: int = 3,
    ) -> List[str]:
        """Explain an anomalous window by ranking top deviating features by z-score.

        Computes z = (observed - benign_mean) / benign_std against baseline training statistics.

        Args:
            window_row: Single window feature record (Series, dict, or 1-row DataFrame).
            top_k: Number of top deviating features to return (default: 3).

        Returns:
            List of formatted strings, e.g. ["unique_dst_ports +14.2σ", "pps +8.5σ", ...].
        """
        if not self.is_fitted or self.training_mean is None or self.training_std is None:
            raise RuntimeError("IsolationForestAnomalyDetector must be fitted before calling explain().")

        if isinstance(window_row, pd.DataFrame):
            row_dict = window_row.iloc[0].to_dict()
        elif isinstance(window_row, pd.Series):
            row_dict = window_row.to_dict()
        else:
            row_dict = dict(window_row)

        z_scores: List[Tuple[str, float, float]] = []

        for col in self.feature_columns:
            val = float(pd.to_numeric(row_dict.get(col, 0.0), errors="coerce") or 0.0)
            mu = float(self.training_mean[col])
            sigma = float(self.training_std[col])
            z = (val - mu) / sigma
            z_scores.append((col, z, abs(z)))

        # Sort descending by absolute z-score deviation
        z_scores.sort(key=lambda item: item[2], reverse=True)

        explanations: List[str] = []
        for col, z, _ in z_scores[:top_k]:
            sign_str = f"+{z:.1f}σ" if z >= 0 else f"{z:.1f}σ"
            explanations.append(f"{col} {sign_str}")

        return explanations

    def explain_dict(
        self,
        window_row: Union[pd.Series, dict, pd.DataFrame],
        top_k: int = 5,
    ) -> Dict[str, float]:
        """Return top deviating feature names and their exact z-scores as a dictionary."""
        if not self.is_fitted or self.training_mean is None or self.training_std is None:
            raise RuntimeError("IsolationForestAnomalyDetector must be fitted before calling explain_dict().")

        if isinstance(window_row, pd.DataFrame):
            row_dict = window_row.iloc[0].to_dict()
        elif isinstance(window_row, pd.Series):
            row_dict = window_row.to_dict()
        else:
            row_dict = dict(window_row)

        z_scores: List[Tuple[str, float]] = []
        for col in self.feature_columns:
            val = float(pd.to_numeric(row_dict.get(col, 0.0), errors="coerce") or 0.0)
            mu = float(self.training_mean[col])
            sigma = float(self.training_std[col])
            z = (val - mu) / sigma
            z_scores.append((col, z))

        z_scores.sort(key=lambda item: abs(item[1]), reverse=True)
        return {col: round(z, 2) for col, z in z_scores[:top_k]}

    def save(self, path: Union[str, Path] = DEFAULT_MODEL_PATH) -> Path:
        """Serialize and persist the fitted model artifact using joblib."""
        if not self.is_fitted:
            raise RuntimeError("Cannot save an unfitted model.")

        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        state = {
            "pipeline": self.pipeline,
            "threshold": self.threshold,
            "s_min": self.s_min,
            "s_max": self.s_max,
            "target_fpr": self.target_fpr,
            "random_state": self.random_state,
            "n_estimators": self.n_estimators,
            "feature_columns": self.feature_columns,
            "training_mean": self.training_mean,
            "training_std": self.training_std,
            "is_fitted": self.is_fitted,
        }
        joblib.dump(state, out_path)
        logger.info("Saved IsolationForestAnomalyDetector artifact to %s", out_path)
        return out_path

    @classmethod
    def load(cls, path: Union[str, Path] = DEFAULT_MODEL_PATH) -> "IsolationForestAnomalyDetector":
        """Deserialize and load an IsolationForestAnomalyDetector artifact from disk."""
        in_path = Path(path)
        if not in_path.is_file():
            raise FileNotFoundError(f"Model artifact file not found at {in_path}")

        raw = joblib.load(in_path)
        if isinstance(raw, cls):
            detector = raw
        elif isinstance(raw, dict):
            detector = cls(
                random_state=raw.get("random_state", 42),
                n_estimators=raw.get("n_estimators", 100),
                target_fpr=raw.get("target_fpr", 0.01),
                feature_columns=raw.get("feature_columns"),
            )
            detector.pipeline = raw.get("pipeline")
            detector.threshold = raw.get("threshold", 0.0)
            detector.s_min = raw.get("s_min", -0.5)
            detector.s_max = raw.get("s_max", 0.5)
            detector.training_mean = raw.get("training_mean")
            detector.training_std = raw.get("training_std")
            detector.is_fitted = raw.get("is_fitted", True)
        else:
            raise TypeError(f"Loaded object is of type {type(raw)}, expected dict or {cls}.")

        logger.info("Loaded IsolationForestAnomalyDetector from %s", in_path)
        return detector


def train_supervised_comparison(
    train_pcaps_dir: Union[str, Path] = "data/pcaps",
    holdout_pcaps_dir: Union[str, Path] = "data/pcaps_holdout",
    random_state: int = 42,
    window_size: float = 5.0,
) -> Tuple[RandomForestClassifier, Dict[str, float]]:
    """Train and evaluate an optional supervised RandomForest baseline model for comparison.

    Trains on labelled windows from training PCAPs and evaluates on unseen holdout PCAPs.

    Args:
        train_pcaps_dir: Directory containing training PCAPs and ground-truth CSVs.
        holdout_pcaps_dir: Directory containing holdout evaluation PCAPs and CSVs.
        random_state: Fixed random seed for reproducibility.
        window_size: Aggregation window size in seconds.

    Returns:
        Tuple of (fitted RandomForestClassifier, evaluation metrics dictionary).
    """
    train_dir = Path(train_pcaps_dir)
    holdout_dir = Path(holdout_pcaps_dir)

    def _load_labeled_dataset(directory: Path) -> pd.DataFrame:
        all_dfs: List[pd.DataFrame] = []
        for pcap_file in sorted(directory.glob("*.pcap")):
            lbl_file = directory / f"{pcap_file.stem}_labels.csv"
            pkts = parse_pcap(pcap_file)
            wins = extract_window_features(pkts, window_size=window_size)
            lbls = pd.read_csv(lbl_file) if lbl_file.is_file() else pd.DataFrame()
            labeled = label_windows(wins, lbls)
            all_dfs.append(labeled)
        return pd.concat(all_dfs, ignore_index=True) if all_dfs else pd.DataFrame()

    logger.info("Loading labeled training PCAPs from %s...", train_dir)
    train_df = _load_labeled_dataset(train_dir)
    logger.info("Loading labeled holdout PCAPs from %s...", holdout_dir)
    holdout_df = _load_labeled_dataset(holdout_dir)

    if train_df.empty or holdout_df.empty:
        raise ValueError("Insufficient data to train supervised comparison model.")

    X_train = train_df[FEATURE_COLUMNS].fillna(0.0).values
    y_train = train_df["is_malicious"].astype(int).values

    X_test = holdout_df[FEATURE_COLUMNS].fillna(0.0).values
    y_test = holdout_df["is_malicious"].astype(int).values

    rf = RandomForestClassifier(n_estimators=100, random_state=random_state, n_jobs=-1)
    rf.fit(X_train, y_train)

    y_pred = rf.predict(X_test)
    y_prob = rf.predict_proba(X_test)[:, 1] if len(rf.classes_) > 1 else y_pred

    metrics = {
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, y_prob)) if len(np.unique(y_test)) > 1 else 0.0,
    }

    logger.info(
        "Supervised RandomForest Evaluation on Holdout: Precision=%.4f, Recall=%.4f, F1=%.4f, ROC-AUC=%.4f",
        metrics["precision"],
        metrics["recall"],
        metrics["f1"],
        metrics["roc_auc"],
    )
    return rf, metrics


# Typer CLI application for ML operations
app = typer.Typer(help="SentinelFlow Machine Learning Anomaly Detection CLI")


@app.command("train")
def train(
    benign: Path = typer.Option(
        DEFAULT_BENIGN_PCAP,
        "--benign",
        "-b",
        help="Path to benign baseline PCAP capture file.",
    ),
    out: Path = typer.Option(
        DEFAULT_MODEL_PATH,
        "--out",
        "-o",
        help="Path where serialized Isolation Forest model artifact will be saved.",
    ),
    target_fpr: float = typer.Option(
        0.01,
        "--target-fpr",
        help="Configurable target false positive rate on validation split (default: 0.01 / 1%).",
    ),
    window_size: float = typer.Option(
        5.0,
        "--window",
        help="Window aggregation duration in seconds (default: 5.0).",
    ),
    supervised: bool = typer.Option(
        False,
        "--supervised",
        help="Train optional comparison RandomForest model on labelled datasets.",
    ),
) -> None:
    """Train unsupervised Isolation Forest on benign baseline traffic."""
    if not benign.is_file():
        typer.secho(f"Error: Benign PCAP not found at '{benign}'.", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)

    typer.echo(f"Ingesting benign baseline PCAP: {benign}")
    packets_df = parse_pcap(benign)
    typer.echo(f"Parsed {len(packets_df):,} packets. Extracting window features ({window_size}s)...")
    windows_df = extract_window_features(packets_df, window_size=window_size)
    typer.echo(f"Extracted {len(windows_df):,} benign traffic windows.")

    detector = IsolationForestAnomalyDetector(target_fpr=target_fpr)
    detector.fit(windows_df)

    saved_path = detector.save(out)
    typer.secho(
        f"Successfully trained Isolation Forest and saved artifact to: {saved_path}",
        fg=typer.colors.GREEN,
        bold=True,
    )
    typer.echo(f"Calibrated Decision Threshold: {detector.threshold:.4f} (Target FPR: {target_fpr:.1%})")

    if supervised:
        typer.echo("\nTraining optional comparison RandomForest model on labelled PCAPs...")
        try:
            _, rf_metrics = train_supervised_comparison(window_size=window_size)
            typer.echo("Supervised RandomForest Baseline Results on Holdout:")
            for k, v in rf_metrics.items():
                typer.echo(f"  {k}: {v:.4f}")
        except Exception as exc:  # noqa: BLE001
            typer.secho(f"Warning: Supervised comparison model failed: {exc}", fg=typer.colors.YELLOW)


@app.command("info")
def info(
    model_path: Path = typer.Option(
        DEFAULT_MODEL_PATH,
        "--model",
        "-m",
        help="Path to serialized Isolation Forest artifact.",
    ),
) -> None:
    """Display metadata, calibrated threshold, and feature statistics for a trained model."""
    if not model_path.is_file():
        typer.secho(f"Model not found at {model_path}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    detector = IsolationForestAnomalyDetector.load(model_path)
    typer.secho(f"Loaded SentinelFlow Model from {model_path}", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"  Target FPR: {detector.target_fpr:.2%}")
    typer.echo(f"  Calibrated Threshold: {detector.threshold:.4f}")
    typer.echo(f"  Raw Dynamic Range: [{detector.s_min:.4f}, {detector.s_max:.4f}]")
    typer.echo(f"  Features Count: {len(detector.feature_columns)}")


if __name__ == "__main__":
    app()
