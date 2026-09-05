# ============================================================
# modules/name_module.py
# ============================================================
import itertools
from typing import List

from rich.console import Console
from rich.prompt  import Confirm
from rich.table   import Table
from rich         import box

from .base            import BaseModule, ResultSet
from utils            import safe_get
from username_checker import run_username_check

console = Console()

_WHATSMYNAME_URL = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
)

_BLOCKLIST = {
    "ebay", "amazon", "apple", "google", "microsoft",
    "pornhub", "xvideos", "xhamster",
}


class NameModule(BaseModule):

    @property
    def name(self) -> str:
        return "Name Intelligence"

    def run(self, pivot: str, results: ResultSet) -> None:
        from .paste_module import PasteModule

        parts = pivot.strip().split()
        if len(parts) < 2:
            results.add_error(
                "Name: provide first and last name for best results"
            )

        self._search_dorks(pivot, parts, results)
        usernames = self._generate_usernames(parts, results)
        self._generate_email_candidates(parts, results)
        self._live_username_check(usernames, results)
        PasteModule().sweep(pivot, results, label="Paste / Leak Sites")

    # ── Search dorks ──────────────────────────────────────────
    def _search_dorks(self, name: str, parts: List[str],
                      results: ResultSet) -> None:
        encoded = "+".join(parts)
        quoted  = f'"{name}"'

        dorks = [
            ("Google",         f"https://www.google.com/search?q={quoted}"),
            ("LinkedIn",       f"https://www.linkedin.com/search/results/people/?keywords={encoded}"),
            ("Facebook",       f"https://www.facebook.com/search/people?q={encoded}"),
            ("Twitter/X",      f"https://twitter.com/search?q={quoted}&f=user"),
            ("Instagram",      f"https://www.google.com/search?q=site:instagram.com+{quoted}"),
            ("GitHub",         f"https://github.com/search?q={quoted}&type=users"),
            ("Whitepages",     f"https://www.whitepages.com/name/{'-'.join(parts)}"),
            ("Spokeo",         f"https://www.spokeo.com/{'+'.join(parts)}"),
            ("PeekYou",        f"https://www.peekyou.com/{parts[0].lower()}_{parts[-1].lower()}"
                                if len(parts) >= 2 else ""),
            ("Public Records", f"https://www.google.com/search?q={quoted}+public+records"),
            ("Court Records",  f"https://www.google.com/search?q={quoted}+court+records"),
            ("News Archive",   f"https://www.google.com/search?q={quoted}&tbs=sbd:1"),
        ]

        for label, url in dorks:
            if url:
                results.add("Search Dorks", label, url, "Generated")

    # ── Username candidate generation ─────────────────────────
    def _generate_usernames(self, parts: List[str],
                             results: ResultSet) -> List[str]:
        if len(parts) < 2:
            base = [parts[0].lower()] if parts else []
            for c in base:
                results.add("Username Candidates", c,
                            f"https://whatsmyname.app/?q={c}",
                            "Pattern Generation")
            return base

        f = parts[0].lower()
        l = parts[-1].lower()
        m = parts[1].lower() if len(parts) > 2 else ""

        raw_candidates = [
            f"{f}{l}",
            f"{f}.{l}",
            f"{f}_{l}",
            f"{f[0]}{l}",
            f"{f}{l[0]}",
            f"{l}{f}",
            f"{l}.{f}",
            f"{l}_{f[0]}",
            f"{f[0]}.{l}",
            f"{f[0]}_{l}",
            f"{f}{l[:3]}",
            f"{l}{f[:3]}",
            f"{f[0]}{m[0]}{l}"  if m else None,
            f"{f}.{m[0]}.{l}"  if m else None,
            f"the{f}{l}",
            f"real{f}{l}",
            f"i{f}{l}",
            f"{f}{l}official",
        ]

        candidates = list(dict.fromkeys(c for c in raw_candidates if c))

        for c in candidates:
            results.add("Username Candidates", c,
                        f"https://whatsmyname.app/?q={c}",
                        "Pattern Generation")

        return candidates

    # ── Email pattern candidates ──────────────────────────────
    def _generate_email_candidates(self, parts: List[str],
                                    results: ResultSet) -> None:
        if len(parts) < 2:
            return

        f = parts[0].lower()
        l = parts[-1].lower()

        patterns = [
            f"{f}.{l}", f"{f}{l}", f"{f[0]}{l}",
            f"{f}{l[0]}", f"{l}.{f}", f"{l}{f[0]}",
        ]
        domains = [
            "gmail.com", "outlook.com", "yahoo.com",
            "icloud.com", "protonmail.com", "hotmail.com",
        ]

        for pat, dom in itertools.product(patterns, domains):
            candidate = f"{pat}@{dom}"
            results.add("Email Candidates", candidate,
                        f"https://emailrep.io/{candidate}",
                        "Pattern Generation")

    # ── Live async username enumeration ───────────────────────
    def _live_username_check(self, usernames: List[str],
                              results: ResultSet) -> None:
        from .enrichment_module import EnrichmentModule
        enricher = EnrichmentModule()

        if not usernames:
            return

        console.print(
            f"\n  [bold cyan]→ Fetching WhatsMyName dataset...[/bold cyan]"
        )

        resp = safe_get(_WHATSMYNAME_URL, timeout=20)
        if not resp or resp.status_code != 200:
            results.add_error("WhatsMyName: could not fetch site dataset")
            return

        try:
            data = resp.json()
        except ValueError:
            results.add_error("WhatsMyName: JSON parse error on dataset")
            return

        sites = [
            s for s in data.get("sites", [])
            if s.get("name", "").lower() not in _BLOCKLIST
            and s.get("uri_check")
            and "{account}" in s.get("uri_check", "")
            and s.get("e_string")
        ]

        total_checks = len(sites) * len(usernames)

        console.print(
            f"  [dim]Dataset loaded — "
            f"{len(sites)} sites · "
            f"{len(usernames)} username candidates · "
            f"{total_checks} total checks[/dim]\n"
        )

        hits = run_username_check(sites, usernames, show_progress=True)

        if hits:
            console.print(
                f"\n  [bold green]✓ {len(hits)} account(s) confirmed[/bold green]\n"
            )

            table = Table(
                box=box.SIMPLE_HEAD,
                show_header=True,
                header_style="bold green",
                border_style="dim",
                padding=(0, 1),
            )
            table.add_column("Site",     style="bold white", min_width=20)
            table.add_column("Username", style="cyan",       min_width=18)
            table.add_column("URL",      style="dim",        min_width=45)
            table.add_column("Signal",   style="green",      min_width=10)

            for hit in sorted(hits, key=lambda h: h.site_name.lower()):
                table.add_row(
                    hit.site_name,
                    hit.username,
                    hit.url,
                    hit.detail,
                )
                results.add(
                    "Username Hits (Live)",
                    f"{hit.site_name} — {hit.username}",
                    hit.url,
                    "WhatsMyName async check",
                )

            console.print(table)

            enrich = Confirm.ask(
                f"\n  Enrich {len(hits)} confirmed profile(s) "
                f"(scrape bio, avatar, links)?",
                default=True,
            )
            if enrich:
                for hit in hits:
                    console.print(
                        f"  [dim]→ Enriching {hit.site_name} "
                        f"({hit.username})...[/dim]"
                    )
                    enricher.enrich(hit.url, hit.site_name, results)

        else:
            console.print(
                "  [dim]No confirmed accounts found across "
                f"{len(sites)} sites.[/dim]\n"
            )
            results.add(
                "Username Hits (Live)",
                "Result",
                f"No hits across {len(sites)} sites checked",
                "WhatsMyName async check",
            )

        results.add(
            "Username Hits (Live)",
            "Sites Checked",
            str(len(sites)),
            "WhatsMyName dataset",
        )
        results.add(
            "Username Hits (Live)",
            "Candidates Tested",
            ", ".join(usernames),
            "WhatsMyName dataset",
        )
        results.add(
            "Username Hits (Live)",
            "Total Requests Made",
            str(total_checks),
            "WhatsMyName async engine",
        )
