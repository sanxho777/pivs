# ============================================================
# pivot_chain.py  (full replacement)
# ============================================================
from __future__ import annotations

import re
import time
from dataclasses  import dataclass, field
from typing       import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from rich.console import Console
from rich.tree    import Tree

from modules.base import ResultSet

console = Console()

_EMAIL_RE  = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_IP_RE     = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}\b"
)

# Domains that generate reverse image search links — never queue as pivots
_REVERSE_IMAGE_HOSTS = {
    "lens.google.com",
    "tineye.com",
    "yandex.com",
    "www.bing.com",
    "bing.com",
}

# Domains whose generated output links should never be re-queued
_OUTPUT_LINK_SKIP = {
    "google.com", "www.google.com",
    "whatsmyname.app",
    "emailrep.io",
    "truecaller.com", "www.truecaller.com",
    "wa.me",
    "linkedin.com", "www.linkedin.com",
    "whitepages.com", "www.whitepages.com",
    "spokeo.com", "www.spokeo.com",
    "twitter.com", "x.com",
    "peekyou.com", "www.peekyou.com",
    "bgp.he.net",
    "shodan.io", "www.shodan.io",
    "virustotal.com", "www.virustotal.com",
    "urlscan.io",
    "securitytrails.com",
    "web.archive.org", "archive.org",
    "dnsdumpster.com",
}

MAX_DEPTH  = 3
MAX_PIVOTS = 30

_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp", "tiff", "bmp"}


def _is_direct_image_url(url: str) -> bool:
    """
    Returns True only for URLs whose PATH ends with a real image
    extension — excludes reverse image search engines and proxy
    URLs that merely contain image extensions in their query strings.
    """
    try:
        parsed = urlparse(url)
        # Skip known reverse image search / output-only hosts
        host = parsed.netloc.lower().lstrip("www.")
        if host in _REVERSE_IMAGE_HOSTS or parsed.netloc in _REVERSE_IMAGE_HOSTS:
            return False
        # The actual PATH (before ?) must end with an image extension
        path = parsed.path.lower().rstrip("/")
        ext  = path.rsplit(".", 1)[-1] if "." in path else ""
        return ext in _IMAGE_EXTENSIONS
    except Exception:
        return False


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


@dataclass
class PivotNode:
    pivot:      str
    pivot_type: str
    depth:      int
    parent:     Optional[str]
    results:    Optional[ResultSet] = None
    children:   List[str]          = field(default_factory=list)


class PivotGraph:

    def __init__(self) -> None:
        self.nodes:   Dict[str, PivotNode] = {}
        self.visited: Set[str]             = set()

    def register(self, pivot: str, pivot_type: str,
                 depth: int, parent: Optional[str]) -> PivotNode:
        node = PivotNode(pivot=pivot, pivot_type=pivot_type,
                         depth=depth, parent=parent)
        self.nodes[pivot] = node
        self.visited.add(pivot.lower())
        if parent and parent in self.nodes:
            self.nodes[parent].children.append(pivot)
        return node

    def seen(self, pivot: str) -> bool:
        return pivot.lower() in self.visited

    def total(self) -> int:
        return len(self.nodes)

    def attach_results(self, pivot: str, results: ResultSet) -> None:
        if pivot in self.nodes:
            self.nodes[pivot].results = results

    def render_tree(self) -> None:
        roots = [n for n in self.nodes.values() if n.parent is None]
        console.print("\n  [bold cyan]── Pivot Chain Graph[/bold cyan]")

        def _build(node: PivotNode, tree: Tree) -> None:
            for child_key in node.children:
                child = self.nodes.get(child_key)
                if not child:
                    continue
                # Skip __enrich__ internal markers from the visible tree
                if child.pivot_type == "__enrich__":
                    continue
                count  = len(child.results.findings) if child.results else 0
                errors = len(child.results.errors)   if child.results else 0
                label  = (
                    f"[cyan]{child.pivot[:80]}[/cyan] "
                    f"[dim]({child.pivot_type})[/dim] "
                    f"[green]{count} findings[/green]"
                )
                if errors:
                    label += f" [red]{errors} err[/red]"
                branch = tree.add(label)
                _build(child, branch)

        for root in roots:
            if root.pivot_type == "__enrich__":
                continue
            count  = len(root.results.findings) if root.results else 0
            errors = len(root.results.errors)   if root.results else 0
            label  = (
                f"[bold white]{root.pivot[:80]}[/bold white] "
                f"[dim]({root.pivot_type})[/dim] "
                f"[green]{count} findings[/green]"
            )
            if errors:
                label += f" [red]{errors} err[/red]"
            t = Tree(label)
            _build(root, t)
            console.print(t)


def discover_chains(results: ResultSet,
                    graph:   PivotGraph,
                    current_depth: int) -> List[Tuple[str, str]]:

    from detector import classify, type_label, PivotType, clean

    candidates: List[Tuple[str, str]] = []

    if current_depth >= MAX_DEPTH:
        return candidates

    for finding in results.findings:
        val = finding.value.strip()
        if not val:
            continue

        val_host = _host(val)

        # ── Skip all generated output/navigation links ────────
        if val_host in _OUTPUT_LINK_SKIP:
            continue
        if val_host in _REVERSE_IMAGE_HOSTS:
            continue

        # Skip obviously generated search dork lines
        if any(x in val for x in [
            "google.com/search", "whatsmyname.app",
            "emailrep.io", "wa.me/", "linkedin.com/search",
            "whitepages.com/name", "bgp.he.net",
            "shodan.io/search", "virustotal.com/gui",
            "urlscan.io/search", "web.archive.org",
            "dnsdumpster.com", "securitytrails.com",
        ]):
            continue

        # ── Direct image URLs only (path must end in ext) ─────
        if val.startswith("http") and _is_direct_image_url(val):
            if not graph.seen(val):
                candidates.append((val, "Image"))
            continue

        # ── Email addresses ───────────────────────────────────
        for em in _EMAIL_RE.findall(val):
            if not graph.seen(em) and em.lower() != results.pivot.lower():
                pt = classify(clean(em))
                if pt == PivotType.EMAIL:
                    candidates.append((em, "Email Address"))

        # ── IP addresses ──────────────────────────────────────
        for match in re.finditer(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", val):
            ip = match.group(1)
            if not graph.seen(ip) and ip != results.pivot:
                pt = classify(ip)
                if pt == PivotType.IP_ADDRESS:
                    candidates.append((ip, "IP Address"))

        # ── Domain names — high-signal categories only ────────
        if finding.category in (
            "DNS", "DNS — A", "DNS — AAAA", "DNS / Mail",
            "Network", "Shared Hosting",
            "Domain", "Domain WHOIS", "WHOIS",
            "Subdomains", "Certificate Transparency",
        ):
            for dm in _DOMAIN_RE.findall(val):
                dm = dm.lower().rstrip(".")
                if graph.seen(dm) or dm == results.pivot.lower():
                    continue
                if _host(f"https://{dm}") in _OUTPUT_LINK_SKIP:
                    continue
                pt = classify(dm)
                if pt == PivotType.DOMAIN:
                    candidates.append((dm, "Domain"))

        # ── Profile hits → enrichment marker ─────────────────
        if (finding.category == "Username Hits (Live)"
                and val.startswith("http")):
            key = f"__enrich__{val}"
            if not graph.seen(key):
                candidates.append((key, "__enrich__"))

    # Deduplicate
    seen_local: Set[str] = set()
    unique: List[Tuple[str, str]] = []
    for item in candidates:
        if item[0].lower() not in seen_local:
            seen_local.add(item[0].lower())
            unique.append(item)

    return unique


def run_chain(
    initial_pivot: str,
    initial_type:  str,
    run_module_fn,
    interactive:   bool = True,
) -> PivotGraph:

    from detector import classify, type_label, clean, PivotType

    graph = PivotGraph()
    queue: List[Tuple[str, str, int, Optional[str]]] = [
        (initial_pivot, initial_type, 0, None)
    ]

    while queue and graph.total() < MAX_PIVOTS:
        pivot, p_type, depth, parent = queue.pop(0)

        if graph.seen(pivot):
            continue

        node = graph.register(pivot, p_type, depth, parent)

        # Internal enrichment markers — register for graph only, don't run
        if p_type == "__enrich__":
            continue

        indent = "  " * depth
        console.print(
            f"\n  [bold green]{indent}→ Chaining:[/bold green] "
            f"[cyan]{pivot[:100]}[/cyan] "
            f"[dim]({p_type})[/dim]"
        )

        results = run_module_fn(pivot, p_type)
        graph.attach_results(pivot, results)

        chains = discover_chains(results, graph, depth)

        # Filter __enrich__ from the count shown to user
        visible_chains = [c for c in chains if c[1] != "__enrich__"]

        if visible_chains:
            console.print(
                f"  {indent}[dim]Discovered "
                f"{len(visible_chains)} new pivot(s)[/dim]"
            )
            if interactive and depth == 0:
                from rich.prompt import Confirm
                proceed = Confirm.ask(
                    f"  Follow {len(visible_chains)} discovered pivot(s)?",
                    default=True,
                )
                if not proceed:
                    chains = []

        for child_pivot, child_type in chains:
            if not graph.seen(child_pivot):
                queue.append((child_pivot, child_type, depth + 1, pivot))

        time.sleep(0.3)

    return graph
