from rich.console import Console
from rich.table import Table
from bluehound.core.graph import GraphConnector
from pathlib import Path
import sys

console = Console()


def run_preflight_checks(graph: GraphConnector, snapshot_dir: Path) -> None:
    """
    Perform environment validation before ingestion.

    Checks:
    - Neo4j connectivity
    - Write permissions on snapshot directory
    - Graph accessibility
    """

    console.print("[bold cyan]Running preflight checks...[/bold cyan]\n")

    results = []

    # Neo4j connectivity
    try:
        graph.connect()
        results.append(("Neo4j connectivity", "PASS"))
    except Exception as e:
        results.append(("Neo4j connectivity", "FAIL"))
        _print_results(results)
        console.print(f"[bold red]Cannot connect to Neo4j: {e}[/bold red]")
        sys.exit(1)

    # Snapshot directory writable
    try:
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        test_file = snapshot_dir / ".write_test"
        test_file.write_text("test")
        test_file.unlink()
        results.append(("Snapshot directory writable", "PASS"))
    except Exception:
        results.append(("Snapshot directory writable", "FAIL"))
        _print_results(results)
        console.print("[bold red]Snapshot directory is not writable[/bold red]")
        sys.exit(1)

    # Graph access sanity check
    try:
        graph.run_read_query("MATCH (n) RETURN count(n) AS count")
        results.append(("Graph query test", "PASS"))
    except Exception:
        results.append(("Graph query test", "FAIL"))
        _print_results(results)
        console.print("[bold red]Cannot query Neo4j graph[/bold red]")
        sys.exit(1)

    _print_results(results)
    console.print("[bold green]✓ Preflight checks passed[/bold green]\n")


def _print_results(results):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Check")
    table.add_column("Status")

    for check, status in results:
        style = "green" if status == "PASS" else "red"
        table.add_row(check, f"[{style}]{status}[/{style}]")

    console.print(table)
