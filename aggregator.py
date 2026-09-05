# ============================================================
# aggregator.py
# ============================================================
import json
import csv
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table   import Table
from rich         import box
from rich.panel   import Panel
from rich.text    import Text

from modules.base import ResultSet

console = Console()


def print_results(results: ResultSet) -> None:
    # Header banner
    header = Text()
    header.append("PIVOT", style="bold green")
    header.append("HARVEST", style="bold white")
    header.append("  ·  ", style="dim")
    header.append(results.pivot, style="bold cyan")
    header.append(f"  [{results.pivot_type}]", style="dim yellow")

    console.print(Panel(header, border_style="green", padding=(0, 2)))
    console.print(f"  [dim]Findings:[/dim] [bold]{len(results.findings)}[/bold]"
                  f"   [dim]Errors:[/dim] [bold red]{len(results.errors)}[/bold red]\n")

    # Group findings by category
    grouped: dict = {}
    for f in results.findings:
        grouped.setdefault(f.category, []).append(f)

    for category, items in grouped.items():
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            padding=(0, 1),
            expand=False,
        )
        table.add_column("Key",    style="green",  min_width=28, max_width=35)
        table.add_column("Value",  style="white",  min_width=40, max_width=70)
        table.add_column("Source", style="dim",    min_width=15)

        for item in items:
            table.add_row(item.key, item.value, item.source)

        console.print(f"  [bold yellow]── {category}[/bold yellow]")
        console.print(table)

    # Errors
    if results.errors:
        console.print("\n  [bold red]── Errors[/bold red]")
        for err in results.errors:
            console.print(f"  [red]! {err}[/red]")


def export_json(results: ResultSet, path: str) -> None:
    data = {
        "pivot":      results.pivot,
        "pivot_type": results.pivot_type,
        "findings": [
            {
                "category": f.category,
                "key":      f.key,
                "value":    f.value,
                "source":   f.source,
            }
            for f in results.findings
        ],
        "errors": results.errors,
    }
    Path(path).write_text(json.dumps(data, indent=2, default=str))
    console.print(f"\n  [green]✓ Exported JSON →[/green] {path}")


def export_csv(results: ResultSet, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["Pivot", "PivotType", "Category", "Key", "Value", "Source"])
        for f in results.findings:
            writer.writerow([
                results.pivot, results.pivot_type,
                f.category, f.key, f.value, f.source,
            ])
    console.print(f"\n  [green]✓ Exported CSV →[/green] {path}")
