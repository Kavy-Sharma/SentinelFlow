"""Command Line Interface (CLI) for SentinelFlow.

Provides Typer subcommands for PCAP ingestion, benign baseline ML training,
threat detection, accuracy evaluation, and performance benchmarking.
"""

import typer

app = typer.Typer(
    name="sentinelflow",
    help="SentinelFlow: Explainable Hybrid Network Intrusion Detection System CLI",
    add_completion=False,
)


@app.callback()
def main() -> None:
    """SentinelFlow Hybrid NIDS CLI."""
    pass


if __name__ == "__main__":
    app()

