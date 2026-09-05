import argparse
import sys

from rich.console import Console
from rich.prompt  import Prompt

from detector    import classify, type_label, clean, PivotType
from aggregator  import print_results, export_json, export_csv
from pivot_chain import run_chain
from modules.base              import ResultSet
from modules.ip_module         import IPModule
from modules.email_module      import EmailModule
from modules.phone_module      import PhoneModule
from modules.name_module       import NameModule
from modules.username_module   import UsernameModule
from modules.domain_module     import DomainModule
from modules.exif_module       import ExifModule
from modules.vin_module        import VINModule
from modules.license_plate_module import LicensePlateModule

console = Console()

BANNER = r"""
  ██████╗ ██╗██╗   ██╗ ██████╗ ████████╗    ██╗  ██╗ █████╗ ██████╗ ██╗   ██╗███████╗███████╗████████╗
  ██╔══██╗██║██║   ██║██╔═══██╗╚══██╔══╝    ██║  ██║██╔══██╗██╔══██╗██║   ██║██╔════╝██╔════╝╚══██╔══╝
  ██████╔╝██║██║   ██║██║   ██║   ██║       ███████║███████║██████╔╝██║   ██║█████╗  ███████╗   ██║
  ██╔═══╝ ██║╚██╗ ██╔╝██║   ██║   ██║       ██╔══██║██╔══██║██╔══██╗╚██╗ ██╔╝██╔══╝  ╚════██║   ██║
  ██║     ██║ ╚████╔╝ ╚██████╔╝   ██║       ██║  ██║██║  ██║██║  ██║ ╚████╔╝ ███████╗███████║   ██║
  ╚═╝     ╚═╝  ╚═══╝   ╚═════╝    ╚═╝       ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚══════╝   ╚═╝
"""

MODULE_MAP = {
    PivotType.IP_ADDRESS:    IPModule,
    PivotType.EMAIL:         EmailModule,
    PivotType.PHONE:         PhoneModule,
    PivotType.NAME:          NameModule,
    PivotType.USERNAME:      UsernameModule,
    PivotType.DOMAIN:        DomainModule,
    PivotType.IMAGE:         ExifModule,
    PivotType.VIN:           VINModule,
    PivotType.LICENSE_PLATE: LicensePlateModule,
}


def run_single_module(pivot: str, pivot_type_label: str) -> ResultSet:
    results    = ResultSet(pivot=pivot, pivot_type=pivot_type_label)
    pt         = classify(pivot)
    module_cls = MODULE_MAP.get(pt)

    if not module_cls:
        results.add_error(f"No module for pivot type: {pivot_type_label}")
        return results

    module = module_cls()

    console.print(f"  [dim]→ {module.name}[/dim]")
    module.run(pivot, results)

    console.print(f"  [dim]→ Enriching {module.name} results...[/dim]")
    module.enrich(pivot, results)

    return results


def _run_no_enrich(pivot: str, pivot_type_label: str) -> ResultSet:
    results    = ResultSet(pivot=pivot, pivot_type=pivot_type_label)
    pt         = classify(pivot)
    module_cls = MODULE_MAP.get(pt)

    if not module_cls:
        results.add_error(f"No module for pivot type: {pivot_type_label}")
        return results

    module = module_cls()
    console.print(f"  [dim]→ {module.name}[/dim]")
    module.run(pivot, results)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PivotHarvest — free OSINT pivot engine"
    )
    parser.add_argument(
        "pivot", nargs="?",
        help=(
            "Email, IP, phone, full name, username, domain, "
            "image URL, VIN, or license plate"
        ),
    )
    parser.add_argument("--json",      metavar="FILE",
                        help="Export all results as JSON")
    parser.add_argument("--csv",       metavar="FILE",
                        help="Export all results as CSV")
    parser.add_argument("--no-chain",  action="store_true",
                        help="Disable pivot chaining")
    parser.add_argument("--no-enrich", action="store_true",
                        help="Skip second-pass enrichment")
    parser.add_argument("--depth",     type=int, default=3,
                        help="Max chain depth (default: 3)")
    args = parser.parse_args()

    console.print(f"[green]{BANNER}[/green]")
    console.print(
        "  [dim]Free OSINT pivot engine  ·  zero paid APIs  ·  "
        "chaining + enrichment + VIN/plate enabled[/dim]\n"
    )

    raw = args.pivot
    if not raw:
        raw = Prompt.ask(
            "  [bold cyan]Enter pivot[/bold cyan] "
            "[dim](email / IP / phone / name / username / "
            "domain / image URL / VIN / plate)[/dim]"
        )

    pivot = clean(raw)
    if not pivot:
        console.print("[red]  No input provided.[/red]")
        sys.exit(1)

    pivot_type = classify(pivot)
    label      = type_label(pivot_type)

    if pivot_type == PivotType.UNKNOWN:
        console.print(
            f"[red]  Could not classify '{pivot}'.[/red]\n"
            "  [dim]Tips:\n"
            "    Full name     →  John Smith\n"
            "    Username      →  sandyballs_sancho\n"
            "    IP            →  8.8.8.8\n"
            "    Email         →  user@domain.com\n"
            "    Phone         →  +1 415 555 0132\n"
            "    Domain        →  example.com\n"
            "    Image URL     →  https://example.com/photo.jpg\n"
            "    VIN           →  1HGBH41JXMN109186\n"
            "    License Plate →  ABC1234[/dim]"
        )
        sys.exit(1)

    console.print(
        f"  [dim]Classified as[/dim] [bold yellow]{label}[/bold yellow]\n"
    )

    run_fn = _run_no_enrich if args.no_enrich else run_single_module

    # ── Chain mode ─────────────────────────────────────────────
    if not args.no_chain:
        import pivot_chain
        pivot_chain.MAX_DEPTH = args.depth

        graph = run_chain(
            initial_pivot = pivot,
            initial_type  = label,
            run_module_fn = run_fn,
            interactive   = True,
        )

        console.print(
            f"\n  [bold cyan]── Chain Complete — "
            f"{graph.total()} pivot(s) processed[/bold cyan]\n"
        )

        all_findings = 0
        for node in graph.nodes.values():
            if node.results:
                print_results(node.results)
                all_findings += len(node.results.findings)

        graph.render_tree()
        console.print(
            f"\n  [bold green]Total findings across all pivots: "
            f"{all_findings}[/bold green]"
        )

        if args.json or args.csv:
            merged = ResultSet(pivot=pivot, pivot_type=label)
            for node in graph.nodes.values():
                if node.results:
                    merged.findings.extend(node.results.findings)
                    merged.errors.extend(node.results.errors)
            if args.json:
                export_json(merged, args.json)
            if args.csv:
                export_csv(merged, args.csv)
        else:
            choice = Prompt.ask(
                "\n  [dim]Export all results?[/dim]",
                choices=["json", "csv", "no"],
                default="no",
            )
            if choice != "no":
                merged = ResultSet(pivot=pivot, pivot_type=label)
                for node in graph.nodes.values():
                    if node.results:
                        merged.findings.extend(node.results.findings)
                        merged.errors.extend(node.results.errors)
                if choice == "json":
                    export_json(merged, "results.json")
                elif choice == "csv":
                    export_csv(merged, "results.csv")

    # ── Single module mode ─────────────────────────────────────
    else:
        results = run_fn(pivot, label)
        print_results(results)

        if args.json:
            export_json(results, args.json)
        if args.csv:
            export_csv(results, args.csv)

        if not args.json and not args.csv:
            choice = Prompt.ask(
                "\n  [dim]Export?[/dim]",
                choices=["json", "csv", "no"],
                default="no",
            )
            if choice == "json":
                export_json(results, "results.json")
            elif choice == "csv":
                export_csv(results, "results.csv")


if __name__ == "__main__":
    main()
