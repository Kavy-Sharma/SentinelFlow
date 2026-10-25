"""Command Line Interface (CLI) for SentinelFlow.

Provides high-performance Typer subcommands for PCAP threat detection, accuracy evaluation,
performance benchmarking, and ML model training. Formats all outputs with Rich tables.
"""

import sys

# Configure UTF-8 encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from enum import Enum
import logging
from pathlib import Path
from typing import List, Optional

import rich
from rich.box import ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer

from sentinelflow.attack_map import AlertExplanation, ConfidenceLevel
from sentinelflow.benchmark import run_benchmarks
from sentinelflow.evaluate import evaluate_dataset
from sentinelflow.features import extract_window_features
from sentinelflow.fusion import (
    export_alerts_csv,
    export_alerts_json,
    export_incident_report_html,
    fuse_detections,
    load_fusion_config,
)
from sentinelflow.ml import (
    DEFAULT_BENIGN_PCAP,
    DEFAULT_MODEL_PATH,
    IsolationForestAnomalyDetector,
)
from sentinelflow.parser import parse_pcap
from sentinelflow.rules import detect_all_rules, load_rules_config

logger = logging.getLogger(__name__)
console = Console()

app = typer.Typer(
    name="sentinelflow",
    help="SentinelFlow: Explainable Hybrid Network Intrusion Detection System",
    add_completion=False,
    no_args_is_help=True,
)


class DetectionMode(str, Enum):
    """Detection engine operation mode."""

    HYBRID = "hybrid"
    RULES = "rules"
    ML = "ml"


@app.command("detect")
def detect(
    pcap: Path = typer.Argument(
        ...,
        help="Path to network packet capture file (.pcap).",
        exists=True,
        readable=True,
    ),
    mode: DetectionMode = typer.Option(
        DetectionMode.HYBRID,
        "--mode",
        "-m",
        help="Detection strategy: 'hybrid' (rules + ML fusion), 'rules' (deterministic only), or 'ml' (Isolation Forest only).",
    ),
    out: Optional[Path] = typer.Option(
        None,
        "--out",
        "-o",
        help="Directory to export alerts JSON, CSV, and HTML incident report.",
    ),
    model: Path = typer.Option(
        DEFAULT_MODEL_PATH,
        "--model",
        help="Path to trained Isolation Forest model artifact.",
    ),
    window: float = typer.Option(
        5.0,
        "--window",
        "-w",
        help="Window aggregation duration in seconds (default: 5.0).",
    ),
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to custom configuration YAML (defaults to config/default.yaml).",
    ),
) -> None:
    """Detect network intrusions and anomalies in a PCAP capture."""
    console.print(
        Panel.fit(
            f"[bold cyan]SentinelFlow NIDS Detection Engine[/bold cyan]\n"
            f"[dim]Analyzing target PCAP:[/dim] [bold white]{pcap}[/bold white]\n"
            f"[dim]Operation Mode:[/dim] [bold yellow]{mode.value.upper()}[/bold yellow] | "
            f"[dim]Window Duration:[/dim] [white]{window:.1f}s[/white]",
            border_style="cyan",
        )
    )

    # 1. PCAP Parsing & Feature Extraction
    with console.status("[bold green]Parsing network packets...", spinner="dots"):
        packets_df = parse_pcap(pcap)
    console.print(f"  [green][OK][/green] Parsed [bold]{len(packets_df):,}[/bold] packets.")

    with console.status("[bold green]Extracting per-source time-window traffic features...", spinner="dots"):
        windows_df = extract_window_features(packets_df, window_size=window)
    console.print(f"  [green][OK][/green] Extracted [bold]{len(windows_df):,}[/bold] traffic windows.")

    # 2. Execute Detection Strategy
    rule_alerts = []
    ml_detector: Optional[IsolationForestAnomalyDetector] = None

    if mode in (DetectionMode.HYBRID, DetectionMode.RULES):
        rule_cfg = load_rules_config(config)
        rule_alerts = detect_all_rules(windows_df, packets_df=packets_df, config=rule_cfg, merge_events=True)

    if mode in (DetectionMode.HYBRID, DetectionMode.ML):
        if model.is_file():
            ml_detector = IsolationForestAnomalyDetector.load(model)
        else:
            if mode == DetectionMode.ML:
                console.print(f"[bold red]Error:[/bold red] ML model file not found at '{model}'. Run `sentinelflow train` first.")
                raise typer.Exit(code=1)
            console.print(f"[yellow]Warning:[/yellow] Model '{model}' not found. Falling back to rules only.")

    fusion_cfg = load_fusion_config(config)

    if mode == DetectionMode.RULES:
        alerts = [a.to_explanation() for a in rule_alerts]
    else:
        alerts = fuse_detections(
            rule_alerts=rule_alerts,
            windows_df=windows_df,
            ml_detector=ml_detector,
            config=fusion_cfg,
            packets_df=packets_df,
        )

    # 3. Present Results in Terminal using Rich Table
    console.print()
    if not alerts:
        console.print(
            Panel(
                "[bold green][CLEAN] ZERO THREAT DETECTIONS[/bold green]\n"
                "[dim]All observed network flows conform to benign baseline behavior.[/dim]",
                border_style="green",
            )
        )
    else:
        table = Table(
            title=f"Detected Security Incidents ({len(alerts)} alerts)",
            box=ROUNDED,
            header_style="bold cyan",
            border_style="dim white",
        )
        table.add_column("#", justify="center", style="dim", width=4)
        table.add_column("Severity", justify="center", width=12)
        table.add_column("Conf.", justify="center", width=8)
        table.add_column("Technique", style="bold magenta", width=10)
        table.add_column("Threat / Detector Title", style="bold white", width=26)
        table.add_column("Attacker IP", style="bold red", width=16)
        table.add_column("Target IP", style="white", width=16)
        table.add_column("Duration", justify="right", width=9)
        table.add_column("Key Evidence / Deviations", style="dim")

        for i, a in enumerate(alerts, 1):
            # Severity color coding
            if a.severity >= 80:
                sev_style = f"[bold red]{a.severity} HIGH[/bold red]"
            elif a.severity >= 50:
                sev_style = f"[bold yellow]{a.severity} MED[/bold yellow]"
            else:
                sev_style = f"[bold cyan]{a.severity} LOW[/bold cyan]"

            # Confidence styling
            conf_str = a.confidence.value if isinstance(a.confidence, ConfidenceLevel) else str(a.confidence)
            if conf_str == "HIGH":
                conf_style = "[bold green]HIGH[/bold green]"
            elif conf_str == "MEDIUM":
                conf_style = "[yellow]MED[/yellow]"
            else:
                conf_style = "[dim]LOW[/dim]"

            dur_str = f"{a.duration:.1f}s" if a.duration > 0 else "-"
            target_str = a.target_ip or "-"

            # Key deviations snippet
            evid_parts = []
            if a.top_deviating_features:
                for f_name, z in list(a.top_deviating_features.items())[:2]:
                    sign = f"+{z:.1f}σ" if z >= 0 else f"{z:.1f}σ"
                    evid_parts.append(f"{f_name} {sign}")
            elif a.matched_conditions:
                evid_parts.append(a.matched_conditions[0][:40])

            evidence_str = ", ".join(evid_parts) if evid_parts else "-"

            table.add_row(
                str(i),
                sev_style,
                conf_style,
                a.mitre_technique_id or "-",
                a.detector_name,
                a.source_ip or "-",
                target_str,
                dur_str,
                evidence_str,
            )

        console.print(table)

    # 4. Export Artifacts if --out is requested
    if out:
        out_dir = Path(out)
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = export_alerts_json(alerts, out_dir / "alerts.json")
        csv_path = export_alerts_csv(alerts, out_dir / "alerts.csv")
        html_path = export_incident_report_html(alerts, out_dir / "incident_report.html", pcap_name=pcap.name)

        console.print(
            Panel.fit(
                f"[bold green][OK] Investigation Artifacts Exported Successfully[/bold green]\n"
                f"[dim]JSON Alerts:[/dim]  [cyan]{json_path}[/cyan]\n"
                f"[dim]CSV Table:[/dim]    [cyan]{csv_path}[/cyan]\n"
                f"[dim]HTML Report:[/dim]  [bold cyan]{html_path}[/bold cyan]",
                border_style="green",
            )
        )


@app.command("evaluate")
def evaluate(
    pcaps_dir: Path = typer.Option(
        Path("data/pcaps"),
        "--pcaps-dir",
        "-d",
        help="Directory containing evaluation PCAP captures and *_labels.csv files.",
    ),
    mode: DetectionMode = typer.Option(
        DetectionMode.HYBRID,
        "--mode",
        "-m",
        help="Evaluation detection mode ('hybrid', 'rules', 'ml').",
    ),
    model: Path = typer.Option(
        DEFAULT_MODEL_PATH,
        "--model",
        help="Path to trained Isolation Forest artifact.",
    ),
    window: float = typer.Option(
        5.0,
        "--window",
        "-w",
        help="Window aggregation duration in seconds.",
    ),
) -> None:
    """Evaluate detection engine precision, recall, and F1 metrics on labeled datasets."""
    console.print(
        Panel.fit(
            f"[bold cyan]SentinelFlow Accuracy & Benchmark Evaluation[/bold cyan]\n"
            f"[dim]Dataset Directory:[/dim] [white]{pcaps_dir}[/white] | "
            f"[dim]Mode:[/dim] [bold yellow]{mode.value.upper()}[/bold yellow]",
            border_style="cyan",
        )
    )

    with console.status("[bold green]Evaluating detection engine across dataset scenarios...", spinner="dots"):
        results = evaluate_dataset(
            pcaps_dir=pcaps_dir,
            model_path=model if model.is_file() else None,
            mode=mode.value,
            window_size=window,
        )

    scenarios = results["scenario_evaluations"]

    table = Table(
        title="Per-Scenario Evaluation Metrics",
        box=ROUNDED,
        header_style="bold cyan",
        border_style="dim white",
    )
    table.add_column("Scenario Capture", style="bold white", width=28)
    table.add_column("Windows", justify="right", width=9)
    table.add_column("Malicious", justify="right", width=10)
    table.add_column("Alerts", justify="right", width=8)
    table.add_column("Status", justify="center", width=14)
    table.add_column("Precision", justify="right", width=10)
    table.add_column("Recall", justify="right", width=10)
    table.add_column("Accuracy", justify="right", width=10)
    table.add_column("F1-Score", justify="right", width=10)

    for sc in scenarios:
        if sc.malicious_windows > 0:
            status = "[bold green]DETECTED[/bold green]" if sc.attack_detected else "[bold red]MISSED[/bold red]"
        else:
            status = "[dim]CLEAN BENIGN[/dim]" if sc.detected_alerts_count == 0 else f"[red]{sc.detected_alerts_count} FP[/red]"

        table.add_row(
            sc.scenario,
            f"{sc.total_windows:,}",
            f"{sc.malicious_windows:,}",
            f"{sc.detected_alerts_count:,}",
            status,
            f"{sc.precision:.2%}",
            f"{sc.recall:.2%}",
            f"{sc.accuracy:.2%}",
            f"{sc.f1:.2%}",
        )

    console.print(table)

    # Summary Panel
    w_metrics = results.get("window_metrics", {})
    console.print(
        Panel.fit(
            f"[bold cyan]Incident / Scenario-Level Benchmark (Capture Detection):[/bold cyan]\n"
            f"  [dim]Precision:[/dim] [bold green]{results['overall_precision']:.2%}[/bold green] | "
            f"[dim]Recall:[/dim] [bold green]{results['overall_recall']:.2%}[/bold green] | "
            f"[dim]Accuracy:[/dim] [bold green]{results.get('overall_accuracy', 0.0):.2%}[/bold green] | "
            f"[dim]F1-Score:[/dim] [bold green]{results['overall_f1']:.2%}[/bold green]\n"
            f"  [dim]TP:[/dim] [green]{results['total_true_positives']}[/green] | "
            f"[dim]FP:[/dim] [red]{results['total_false_positives']}[/red] | "
            f"[dim]FN:[/dim] [yellow]{results['total_false_negatives']}[/yellow] | "
            f"[dim]TN:[/dim] [green]{results.get('total_true_negatives', 0)}[/green]\n\n"
            f"[bold magenta]Window-Level Benchmark (5-Second Windows):[/bold magenta]\n"
            f"  [dim]Precision:[/dim] [bold white]{w_metrics.get('precision', 0.0):.2%}[/bold white] | "
            f"[dim]Recall:[/dim] [bold white]{w_metrics.get('recall', 0.0):.2%}[/bold white] | "
            f"[dim]Accuracy:[/dim] [bold white]{w_metrics.get('accuracy', 0.0):.2%}[/bold white] | "
            f"[dim]F1-Score:[/dim] [bold white]{w_metrics.get('f1', 0.0):.2%}[/bold white]\n"
            f"  [dim]TP:[/dim] [green]{w_metrics.get('total_true_positives', 0)}[/green] | "
            f"[dim]FP:[/dim] [red]{w_metrics.get('total_false_positives', 0)}[/red] | "
            f"[dim]FN:[/dim] [yellow]{w_metrics.get('total_false_negatives', 0)}[/yellow] | "
            f"[dim]TN:[/dim] [green]{w_metrics.get('total_true_negatives', 0)}[/green]",
            border_style="green",
        )
    )



@app.command("benchmark")
def benchmark(
    pcaps_dir: Path = typer.Option(
        Path("data/pcaps"),
        "--pcaps-dir",
        "-d",
        help="Directory containing PCAP captures to profile.",
    ),
    model: Path = typer.Option(
        DEFAULT_MODEL_PATH,
        "--model",
        help="Path to trained Isolation Forest artifact.",
    ),
    window: float = typer.Option(
        5.0,
        "--window",
        "-w",
        help="Window aggregation duration in seconds.",
    ),
) -> None:
    """Benchmark offline PCAP parsing throughput, feature latency, and memory consumption."""
    console.print(
        Panel.fit(
            f"[bold cyan]SentinelFlow Pipeline Performance & Throughput Benchmark[/bold cyan]\n"
            f"[dim]Profiling PCAPs in:[/dim] [white]{pcaps_dir}[/white]",
            border_style="cyan",
        )
    )

    pcap_files = sorted(pcaps_dir.glob("*.pcap"))[:4]
    if not pcap_files:
        console.print(f"[bold red]Error:[/bold red] No PCAP files found in '{pcaps_dir}'.")
        raise typer.Exit(code=1)

    with console.status("[bold green]Profiling execution throughput and memory...", spinner="dots"):
        metrics = run_benchmarks(pcap_paths=pcap_files, model_path=model if model.is_file() else None)

    table = Table(
        title="Throughput & Latency Benchmark Results",
        box=ROUNDED,
        header_style="bold cyan",
        border_style="dim white",
    )
    table.add_column("PCAP File", style="bold white", width=24)
    table.add_column("Packets", justify="right", width=9)
    table.add_column("Parse (s)", justify="right", width=10)
    table.add_column("Feat (s)", justify="right", width=10)
    table.add_column("Detect (s)", justify="right", width=10)
    table.add_column("Total (s)", justify="right", width=10)
    table.add_column("Throughput", justify="right", style="bold green", width=14)
    table.add_column("Bandwidth", justify="right", style="cyan", width=12)
    table.add_column("RAM (MB)", justify="right", style="yellow", width=10)

    for m in metrics:
        table.add_row(
            m.pcap_name,
            f"{m.packet_count:,}",
            f"{m.parse_time_sec:.2f}s",
            f"{m.feature_time_sec:.2f}s",
            f"{m.detection_time_sec:.2f}s",
            f"{m.total_time_sec:.2f}s",
            f"{m.packet_throughput_pps:,.0f} pkt/s",
            f"{m.byte_throughput_mb_s:.2f} MB/s",
            f"{m.peak_memory_mb:.1f} MB",
        )

    console.print(table)


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
) -> None:
    """Train unsupervised Isolation Forest model on benign baseline PCAP."""
    from sentinelflow.ml import app as ml_app

    # Invoke ml module training CLI directly
    import sys
    sys.argv = [
        "ml",
        "train",
        "--benign",
        str(benign),
        "--out",
        str(out),
        "--target-fpr",
        str(target_fpr),
        "--window",
        str(window_size),
    ]
    ml_app()


if __name__ == "__main__":
    app()
