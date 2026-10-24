"""Command Line Interface for SentinelFlow Synthetic PCAP Generator.

Supports generating reproducible synthetic scenarios:
python -m sentinelflow.generator --scenario all --seed 42 --out data/pcaps
"""

import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from sentinelflow.generator.engine import ScenarioGenerator
from sentinelflow.generator.models import GeneratorConfig

app = typer.Typer(
    name="generator",
    help="SentinelFlow Synthetic PCAP and Attack Label Generator",
    add_completion=False,
)
console = Console()


@app.command()
def main(
    scenario: str = typer.Option(
        "all",
        "--scenario",
        "-s",
        help="Target scenario to generate ('all', 's1', 's2', 's3', 's4', 's5').",
    ),
    seed: int = typer.Option(
        42,
        "--seed",
        help="Deterministic pseudo-random generator seed.",
    ),
    out: Path = typer.Option(
        Path("data/pcaps"),
        "--out",
        "-o",
        help="Output directory path for generated .pcap and .csv files.",
    ),
    duration: float = typer.Option(
        900.0,
        "--duration",
        "-d",
        help="Simulated time duration in seconds (default: 900s / 15 minutes).",
    ),
    generate_holdout: bool = typer.Option(
        False,
        "--generate-holdout",
        help="Additionally generate holdout dataset under data/pcaps_holdout with seed 1337.",
    ),
    log_level: str = typer.Option(
        "INFO",
        "--log-level",
        help="Logging level (DEBUG, INFO, WARNING, ERROR).",
    ),
) -> None:
    """Generate synthetic network PCAPs and ground-truth attack labels."""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    console.print(
        f"[bold blue]SentinelFlow PCAP Generator[/bold blue] | Scenario: [green]{scenario}[/green] | Seed: [yellow]{seed}[/yellow] | Out: [cyan]{out}[/cyan]"
    )

    config = GeneratorConfig(
        seed=seed,
        simulated_duration_seconds=duration,
        output_dir=out,
    )
    generator = ScenarioGenerator(config)

    scenario_lower = scenario.lower()
    results = {}

    if scenario_lower in ("all", "s1", "s1_benign"):
        console.print("[dim]Generating S1: Benign baseline traffic...[/dim]")
        results.update(generator.generate_s1_benign())

    if scenario_lower in ("all", "s2", "s2_scan"):
        console.print("[dim]Generating S2: Fast and slow port scans...[/dim]")
        results.update(generator.generate_s2_port_scan())

    if scenario_lower in ("all", "s3", "s3_dos"):
        console.print("[dim]Generating S3: SYN & UDP floods with victim telemetry...[/dim]")
        results.update(generator.generate_s3_dos())

    if scenario_lower in ("all", "s4", "s4_additional"):
        console.print("[dim]Generating S4: SSH brute force & ARP spoofing...[/dim]")
        results.update(generator.generate_s4_additional())

    if scenario_lower in ("all", "s5", "s5_ambiguous"):
        console.print("[dim]Generating S5: Ambiguous backup & distributed slow scan...[/dim]")
        results.update(generator.generate_s5_ambiguous())

    # Optional Holdout Set Generation
    if generate_holdout:
        holdout_out = out.parent / f"{out.name}_holdout" if out.name == "pcaps" else Path("data/pcaps_holdout")
        console.print(f"[bold magenta]Generating holdout generalization set into {holdout_out} (seed=1337)...[/bold magenta]")
        holdout_config = GeneratorConfig(
            seed=1337,
            simulated_duration_seconds=duration,
            output_dir=holdout_out,
        )
        holdout_gen = ScenarioGenerator(holdout_config)
        holdout_results = holdout_gen.generate_all()
        results.update({f"holdout_{k}": v for k, v in holdout_results.items()})

    table = Table(title="Generated Dataset Artifacts", show_lines=True)
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Artifact Path", style="green")
    table.add_column("Size (Bytes)", style="yellow", justify="right")

    for key, path in sorted(results.items()):
        size_str = f"{path.stat().st_size:,}" if path.exists() else "N/A"
        table.add_row(key, str(path), size_str)

    console.print(table)
    console.print("[bold green]Synthetic PCAP and label generation complete![/bold green]")


if __name__ == "__main__":
    app()
