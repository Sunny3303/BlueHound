from __future__ import annotations

import json
import sys
from pathlib import Path
from datetime import datetime, timezone

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from bluehound.config.settings import get_neo4j_config
from bluehound.core.graph import GraphConnector
from bluehound.ingestion.sharphound import SharpHoundIngester

from bluehound.cli.preflight import run_preflight_checks

from bluehound.core.graph_view import GraphView
from bluehound.core.detection_context import DetectionContext
from bluehound.detection.engine import DetectionEngine
from bluehound.risk.engine import RiskEngine
from bluehound.output.assembler import ThreatModelAssembler
from bluehound.core.types import SnapshotMetadata, ExposureLevel


console = Console()


def print_banner() -> None:
    banner = """
██████╗ ██╗     ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗
██╔══██╗██║     ██║   ██║██╔════╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
██████╔╝██║     ██║   ██║█████╗  ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
██╔══██╗██║     ██║   ██║██╔══╝  ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
██████╔╝███████╗╚██████╔╝███████╗██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝

Active Directory Threat Modeling Engine v1.0.0
"""
    console.print(banner, style="bold blue")


@click.group()
@click.version_option("1.0.0")
def cli() -> None:
    """BlueHound CLI."""
    pass


@cli.command()
@click.argument("sharphound_zip", type=click.Path(exists=True, path_type=Path))
@click.option("--neo4j-uri", default=None)
@click.option("--neo4j-user", default=None)
@click.option("--neo4j-password", default=None)
@click.option("--output-dir", type=Path, default=Path("snapshots"))
@click.option("--clear-graph", is_flag=True)
def ingest(
    sharphound_zip: Path,
    neo4j_uri: str | None,
    neo4j_user: str | None,
    neo4j_password: str | None,
    output_dir: Path,
    clear_graph: bool,
) -> None:
    """Ingest SharpHound ZIP into Neo4j."""

    print_banner()

    graph: GraphConnector | None = None

    try:
        cfg = get_neo4j_config()

        uri = neo4j_uri or cfg.get("uri")
        user = neo4j_user or cfg.get("username")
        password = neo4j_password or cfg.get("password")

        if not password:
            password = click.prompt("Neo4j password", hide_input=True)

        console.print(f"[cyan][+] Connecting to Neo4j at {uri}...[/cyan]")

        graph = GraphConnector(uri, user, password)
        graph.connect()

        run_preflight_checks(graph, output_dir)

        ingester = SharpHoundIngester(graph)

        if clear_graph:
            if click.confirm("This will delete ALL graph data. Continue?"):
                graph.enable_writes()
                ingester.clear_graph()
                graph.disable_writes()

        console.print(f"[cyan][+] Ingesting {sharphound_zip.name}...[/cyan]")

        graph.enable_writes()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Processing...", total=None)
            metadata = ingester.ingest_zip(sharphound_zip)
            progress.update(task, completed=True)

        graph.disable_writes()

        stats = ingester.stats

        console.print(f"[cyan][+] Loaded {stats['users']:,} users[/cyan]")
        console.print(f"[cyan][+] Loaded {stats['computers']:,} computers[/cyan]")
        console.print(f"[cyan][+] Loaded {stats['groups']:,} groups[/cyan]")
        console.print(f"[cyan][+] Loaded {stats['relationships']:,} relationships[/cyan]")
        console.print(f"[cyan][+] Domain: {metadata.domain_fqdn}[/cyan]")

        snapshot_dir = ingester.save_snapshot_metadata(metadata, output_dir)
        console.print(f"[cyan][+] Snapshot saved: {snapshot_dir}[/cyan]")

        console.print("[bold green]✓ Ingestion complete[/bold green]")

        table = Table(show_header=False)
        table.add_column("Metric")
        table.add_column("Count", justify="right")
        table.add_row("Users", f"{stats['users']:,}")
        table.add_row("Computers", f"{stats['computers']:,}")
        table.add_row("Groups", f"{stats['groups']:,}")
        table.add_row("Relationships", f"{stats['relationships']:,}")

        console.print("\n[bold]Statistics:[/bold]")
        console.print(table)

    except Exception as exc:
        console.print(f"[bold red]✗ {exc}[/bold red]")
        sys.exit(1)

    finally:
        if graph:
            try:
                graph.disable_writes()
            except Exception:
                pass
            graph.disconnect()


@cli.command("list-snapshots")
@click.option("--dir", "snapshot_root", type=Path, default=Path("snapshots"))
def list_snapshots(snapshot_root: Path) -> None:
    """List snapshots."""

    if not snapshot_root.exists():
        console.print("[yellow]No snapshots found.[/yellow]")
        return

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Timestamp")
    table.add_column("Domain")
    table.add_column("Users", justify="right")
    table.add_column("Computers", justify="right")
    table.add_column("Groups", justify="right")

    for sdir in sorted(snapshot_root.iterdir(), reverse=True):
        meta_path = sdir / "metadata.json"
        if not meta_path.exists():
            continue

        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        stats = meta.get("statistics", {})

        table.add_row(
            sdir.name,
            meta.get("domain_fqdn", "UNKNOWN"),
            f"{stats.get('users',0):,}",
            f"{stats.get('computers',0):,}",
            f"{stats.get('groups',0):,}",
        )

    console.print(table)


@cli.command()
@click.argument("snapshot_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--neo4j-uri", default=None)
@click.option("--neo4j-user", default=None)
@click.option("--neo4j-password", default=None)
@click.option("--port", default=8080)
@click.option("--no-dashboard", is_flag=True)
@click.option("--output", type=Path)
def analyze(
    snapshot_dir: Path,
    neo4j_uri: str | None,
    neo4j_user: str | None,
    neo4j_password: str | None,
    port: int,
    no_dashboard: bool,
    output: Path | None,
) -> None:
    """Analyze AD snapshot and generate threat model."""

    print_banner()

    graph: GraphConnector | None = None

    try:

        cfg = get_neo4j_config()

        uri = neo4j_uri or cfg.get("uri")
        user = neo4j_user or cfg.get("username")
        password = neo4j_password or cfg.get("password")

        if not password:
            password = click.prompt("Neo4j password", hide_input=True)

        console.print(f"[cyan][+] Connecting to Neo4j at {uri}...[/cyan]")

        graph = GraphConnector(uri, user, password)
        graph.connect()

        metadata_path = snapshot_dir / "metadata.json"

        if not metadata_path.exists():
            console.print(f"[bold red]✗ No metadata found in {snapshot_dir}[/bold red]")
            sys.exit(1)

        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata_dict = json.load(f)

        snapshot_metadata = SnapshotMetadata(
            version=metadata_dict.get("version", "1.0.0"),
            collected_at=datetime.fromisoformat(metadata_dict["collected_at"]),
            domain_fqdn=metadata_dict["domain_fqdn"],
            collector=metadata_dict.get("collector", "sharphound"),
            signature=metadata_dict.get("signature", ""),
        )

        console.print(f"[cyan][+] Analyzing domain: {snapshot_metadata.domain_fqdn}[/cyan]")

        # Load GraphView
        console.print("[cyan][+] Loading AD data from Neo4j...[/cyan]")

        view = GraphView(graph)
        view.load()

        stats = view.get_statistics()

        console.print(
            f"[cyan][+] Loaded {stats['users']:,} users, {stats['computers']:,} computers, {stats['groups']:,} groups[/cyan]"
        )

        # Warn if Neo4j node counts differ from what was recorded at ingest time,
        # which means another dataset was ingested after this snapshot was captured.
        saved_stats = metadata_dict.get("stats", {})
        saved_users = saved_stats.get("users", None)
        saved_groups = saved_stats.get("groups", None)
        if saved_users is not None and (
            stats["users"] != saved_users or stats["groups"] != saved_groups
        ):
            console.print(
                f"[yellow]⚠ Neo4j graph does not match this snapshot. "
                f"Snapshot recorded {saved_users} users / {saved_groups} groups, "
                f"but Neo4j currently has {stats['users']} users / {stats['groups']} groups. "
                f"Run 'ingest --clear-graph' before analyzing to get accurate per-snapshot results.[/yellow]"
            )

        # Build Detection Context
        console.print("[cyan][+] Building detection context...[/cyan]")

        context = DetectionContext(view)
        context.build()

        # Run Detection Engine
        console.print("[cyan][+] Running detection engine...[/cyan]")

        engine = DetectionEngine(context)
        findings = engine.run_all_detections()

        console.print(f"[cyan][+] Detected {len(findings)} findings[/cyan]")

        # Risk Engine
        console.print("[cyan][+] Computing risk score...[/cyan]")

        risk_engine = RiskEngine(view, context)
        risk_result = risk_engine.compute_risk(findings)

        console.print(f"[cyan][+] Risk score: {risk_result.global_risk_score:.1f}/10[/cyan]")

        # Assemble Threat Model
        assembler = ThreatModelAssembler(view)

        threat_model = assembler.assemble(findings, risk_result, snapshot_metadata)

        # Save JSON
        output_dir = Path(".bluehound/results")
        output_dir.mkdir(parents=True, exist_ok=True)

        if output:
            result_file = output
        else:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
            result_file = output_dir / f"{timestamp}.json"

        with open(result_file, "w", encoding="utf-8") as f:
            f.write(threat_model.to_json())

        console.print(f"[cyan][+] Results saved to: {result_file}[/cyan]")

        _print_analysis_summary(threat_model, None if no_dashboard else port, result_file)

        # Disconnect from Neo4j before the long-running server process starts.
        if graph:
            graph.disconnect()
            graph = None

        if not no_dashboard:
            _start_dashboard(host="127.0.0.1", port=port)

    except Exception as exc:
        console.print(f"[bold red]✗ Analysis failed: {exc}[/bold red]")
        sys.exit(1)

    finally:
        if graph:
            graph.disconnect()

def _start_dashboard(host: str, port: int) -> None:
    """Start the FastAPI dashboard server (blocks until Ctrl-C)."""
    try:
        import uvicorn  # type: ignore[import]
    except ImportError:
        console.print(
            "[yellow]⚠ uvicorn is not installed — dashboard not started.[/yellow]\n"
            "  Install with:  pip install 'uvicorn[standard]'\n"
            "  Then run:      bluehound serve"
        )
        return

    console.print("[dim]Press Ctrl+C to stop the dashboard server[/dim]\n")

    try:
        uvicorn.run(
            "bluehound.api.server:app",
            host=host,
            port=port,
            reload=False,
            log_level="warning",   # keep output tidy after the summary
        )
    except KeyboardInterrupt:
        console.print("\n[cyan][+] Dashboard stopped.[/cyan]")


def _print_analysis_summary(threat_model, dashboard_port, result_file):

    console.print("\n")
    console.print("━" * 80, style="blue")
    console.print("🔵 BlueHound Analysis Complete", style="bold blue", justify="left")
    console.print("━" * 80, style="blue")

    if dashboard_port:
        console.print(f"\n📊 Dashboard: http://localhost:{dashboard_port}")

    console.print(f"\nRisk Score: {threat_model.risk_score:.1f}/10")

    exposure = threat_model.exposure_level.value.replace("-", " ").title()
    console.print(f"Exposure: {exposure}")

    if threat_model.primary_kill_path:
        path = " → ".join(threat_model.primary_kill_path.nodes)
        console.print(f"Primary Kill Path: {path}")

    if threat_model.top_fixes:

        console.print("\nTop Fixes:")

        for i, fix in enumerate(threat_model.top_fixes[:5], 1):
            console.print(f"  {i}. {fix}")

    console.print("\n" + "━" * 80)
    console.print(f"\nFull analysis: {result_file}")
    console.print()


@cli.command()
@click.argument("baseline", type=click.Path(exists=True, path_type=Path))
@click.argument("current", type=click.Path(exists=True, path_type=Path))
@click.option("--output", type=Path, help="Save diff report to file")
@click.option("--format", type=click.Choice(["text", "json"]), default="text")
def diff(
    baseline: Path,
    current: Path,
    output: Path | None,
    format: str,
) -> None:
    """
    Compare two snapshots and show security posture changes.

    Accepts either:
    - Snapshot directories
    - Direct ThreatModelResult JSON files
    """

    print_banner()

    try:
        console.print("[cyan][+] Loading baseline snapshot...[/cyan]")
        baseline_result = _load_threat_model(baseline)

        console.print("[cyan][+] Loading current snapshot...[/cyan]")
        current_result = _load_threat_model(current)

        if baseline_result.metadata.domain_fqdn != current_result.metadata.domain_fqdn:
            console.print(
                f"[yellow]⚠ Domain mismatch: "
                f"{baseline_result.metadata.domain_fqdn} vs "
                f"{current_result.metadata.domain_fqdn}[/yellow]"
            )

        console.print("[cyan][+] Computing snapshot diff...[/cyan]")

        from bluehound.diff.engine import SnapshotDiffEngine

        engine = SnapshotDiffEngine()
        diff_result = engine.compare(baseline_result, current_result)

        if format == "text":
            _print_diff_summary(diff_result, baseline, current)

        if output:
            _save_diff_report(diff_result, output, format)
            console.print(f"\n[cyan][+] Diff report saved: {output}[/cyan]")

        if diff_result.is_regression():
            sys.exit(1)

    except FileNotFoundError as e:
        console.print(f"[bold red]✗ File not found: {e}[/bold red]")
        sys.exit(1)

    except json.JSONDecodeError as e:
        console.print(f"[bold red]✗ Invalid JSON: {e}[/bold red]")
        sys.exit(1)

    except Exception as e:
        console.print(f"[bold red]✗ Diff failed: {e}[/bold red]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)


def _load_threat_model(path: Path):
    """Load ThreatModelResult from JSON file or snapshot directory."""

    from bluehound.core.types import ThreatModelResult

    if path.is_file() and path.suffix == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return ThreatModelResult.from_dict(data)

    if path.is_dir():
        metadata_file = path / "metadata.json"

        if not metadata_file.exists():
            raise FileNotFoundError(f"No metadata.json found in {path}")

        results_dir = Path(".bluehound/results")

        if not results_dir.exists():
            raise FileNotFoundError(
                "No analysis results found. Run analyze first."
            )

        for result_file in sorted(results_dir.glob("*.json")):
            try:
                with open(result_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                return ThreatModelResult.from_dict(data)

            except Exception:
                continue

        raise FileNotFoundError(
            f"No analysis result found for snapshot {path}"
        )

    raise ValueError(f"Invalid path: {path}")


def _print_diff_summary(diff, baseline_path: Path, current_path: Path):

    console.print("\n")
    console.print("━" * 80, style="blue")
    console.print("🔵 BlueHound Snapshot Comparison", style="bold blue", justify="left")
    console.print("━" * 80, style="blue")
    console.print()

    console.print(f"Baseline:  {baseline_path}")
    console.print(f"Current:   {current_path}")

    days = diff.time_delta.days
    hours = diff.time_delta.seconds // 3600

    if days:
        console.print(f"Time:      {days} day(s), {hours} hours")
    else:
        console.print(f"Time:      {hours} hours")

    console.print()
    console.print("━" * 80, style="blue")

    if diff.is_regression():
        console.print("⚠️ SECURITY REGRESSION DETECTED", style="bold red", justify="left")
    elif diff.is_improvement():
        console.print("✓ SECURITY IMPROVEMENT", style="bold green", justify="center")
    else:
        console.print("NO SIGNIFICANT CHANGE", style="bold yellow", justify="center")

    console.print("━" * 80, style="blue")
    console.print()

    sign = "+" if diff.risk_score_delta > 0 else ""
    color = "red" if diff.risk_score_delta > 0 else "green"

    console.print(
        f"Risk Delta: {sign}{diff.risk_score_delta:.1f}",
        style=color,
    )

    console.print(f"Classification: {diff.risk_classification_change}")
    console.print(f"Exposure: {diff.exposure_level_change}")
    console.print()

    if diff.new_findings:
        console.print(f"New Findings: {len(diff.new_findings)}", style="bold")
        for f in diff.new_findings[:5]:
            console.print(f"  • {f.title}")

    if diff.removed_findings:
        console.print(f"\nRemoved Findings: {len(diff.removed_findings)}", style="green")
        for f in diff.removed_findings[:5]:
            console.print(f"  ✓ {f.title}")

    if diff.privilege_creep_detected:
        console.print("\n⚠ Privilege Creep Detected", style="yellow")
        for p in diff.privilege_creep_principals:
            console.print(f"  • {p}")

    if diff.tier0_exposure_regression:
        console.print("\n⚠ Tier-0 Exposure Regression", style="red")
        for p in diff.new_tier0_paths:
            console.print(f"  • {p}")

    console.print()
    console.print("Attack Surface:", style="bold")
    console.print(f"  Blast Radius Δ: {diff.blast_radius_delta * 100:.2f}%")
    console.print(f"  Affected Principals Δ: {diff.affected_principal_delta}")
    console.print("\n" + "━" * 80, style="blue")
    console.print(f"Improvement Score: {diff.improvement_score:+.1f}")


def _save_diff_report(diff, output_path: Path, format: str):

    if format == "json":
        import dataclasses
        from datetime import timedelta

        def serialize(obj):
            if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
                return dataclasses.asdict(obj)
            # datetime → ISO-8601 string  (e.g. "2026-02-10T09:00:00+00:00")
            if hasattr(obj, "isoformat"):
                return obj.isoformat()
            if isinstance(obj, timedelta):
                return obj.total_seconds()
            if hasattr(obj, "value"):
                return obj.value
            raise TypeError(f"Object of type {type(obj).__name__} is not JSON serialisable")

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(diff, f, indent=2, default=serialize)

    else:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(diff.get_summary())


@cli.command()
@click.option("--port", default=8080, show_default=True, help="Port to bind the server to.")
@click.option("--host", default="127.0.0.1", show_default=True, help="Host/interface to listen on.")
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload on code changes.")
@click.option("--dev", is_flag=True, default=False, help="Development mode — React dev server expected on :3000.")
def serve(port: int, host: str, reload: bool, dev: bool) -> None:
    """
    Start the BlueHound dashboard backend server.
    """
    try:
        import uvicorn
    except ImportError:
        console.print(
            "[bold red]✗ uvicorn is not installed.[/bold red]\n"
            "  Install it with:  pip install 'uvicorn[standard]'"
        )
        sys.exit(1)

    console.print("[cyan][+] Starting BlueHound Dashboard Server...[/cyan]")

    if dev:
        console.print("[yellow]⚠ Development mode — CORS open, API on :[/yellow]"
                      f"[yellow]{port}[/yellow]")
        console.print(f"[yellow]  React dev server should be running on :3000[/yellow]")
    else:
        console.print(f"[cyan][+] Dashboard: http://{host}:{port}/[/cyan]")

    console.print()
    console.print("[dim]Press Ctrl+C to stop the server[/dim]")
    console.print()

    try:
        uvicorn.run(
            "bluehound.api.server:app",
            host=host,
            port=port,
            reload=dev or reload,
            log_level="info",
        )
    except KeyboardInterrupt:
        console.print("\n[cyan][+] Server stopped.[/cyan]")


if __name__ == "__main__":
    cli()
