# ============================================================
# modules/username_module.py
# ============================================================
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


class UsernameModule(BaseModule):

    @property
    def name(self) -> str:
        return "Username Intelligence"

    def run(self, pivot: str, results: ResultSet) -> None:
        self._search_dorks(pivot, results)
        self._live_check(pivot, results)

    def _search_dorks(self, username: str, results: ResultSet) -> None:
        dorks = [
            ("Google",      f'https://www.google.com/search?q="{username}"'),
            ("Twitter/X",   f"https://twitter.com/{username}"),
            ("Instagram",   f"https://www.instagram.com/{username}/"),
            ("GitHub",      f"https://github.com/{username}"),
            ("Reddit",      f"https://www.reddit.com/user/{username}"),
            ("TikTok",      f"https://www.tiktok.com/@{username}"),
            ("LinkedIn",    f"https://www.linkedin.com/in/{username}"),
            ("Twitch",      f"https://www.twitch.tv/{username}"),
            ("YouTube",     f"https://www.youtube.com/@{username}"),
            ("Pinterest",   f"https://www.pinterest.com/{username}/"),
            ("Snapchat",    f"https://www.snapchat.com/add/{username}"),
            ("Steam",       f"https://steamcommunity.com/id/{username}"),
            ("WhatsMyName", f"https://whatsmyname.app/?q={username}"),
        ]
        for label, url in dorks:
            results.add("Direct Profile Links", label, url, "Generated")

    def _live_check(self, username: str, results: ResultSet) -> None:
        from .enrichment_module import EnrichmentModule
        enricher = EnrichmentModule()

        console.print(
            "\n  [bold cyan]→ Fetching WhatsMyName dataset...[/bold cyan]"
        )

        resp = safe_get(_WHATSMYNAME_URL, timeout=20)
        if not resp or resp.status_code != 200:
            results.add_error("WhatsMyName: could not fetch dataset")
            return

        try:
            data = resp.json()
        except ValueError:
            results.add_error("WhatsMyName: JSON parse error")
            return

        sites = [
            s for s in data.get("sites", [])
            if s.get("name", "").lower() not in _BLOCKLIST
            and s.get("uri_check")
            and "{account}" in s.get("uri_check", "")
            and s.get("e_string")
        ]

        console.print(
            f"  [dim]Dataset loaded — "
            f"{len(sites)} sites · "
            f"1 username · "
            f"{len(sites)} total checks[/dim]\n"
        )

        hits = run_username_check(sites, [username], show_progress=True)

        if hits:
            console.print(
                f"\n  [bold green]✓ {len(hits)} account(s) confirmed "
                f"for '{username}'[/bold green]\n"
            )

            table = Table(
                box=box.SIMPLE_HEAD,
                show_header=True,
                header_style="bold green",
                border_style="dim",
                padding=(0, 1),
            )
            table.add_column("Site",   style="bold white", min_width=22)
            table.add_column("URL",    style="dim",        min_width=50)
            table.add_column("Signal", style="green",      min_width=10)

            for hit in sorted(hits, key=lambda h: h.site_name.lower()):
                table.add_row(hit.site_name, hit.url, hit.detail)
                results.add(
                    "Username Hits (Live)",
                    hit.site_name,
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
                        f"  [dim]→ Enriching {hit.site_name}...[/dim]"
                    )
                    enricher.enrich(hit.url, hit.site_name, results)

        else:
            console.print(
                f"  [dim]No confirmed accounts found for "
                f"'{username}' across {len(sites)} sites.[/dim]\n"
            )
            results.add(
                "Username Hits (Live)",
                "Result",
                f"No hits across {len(sites)} sites",
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
            username,
            "WhatsMyName dataset",
        )
        results.add(
            "Username Hits (Live)",
            "Total Requests Made",
            str(len(sites)),
            "WhatsMyName async engine",
        )
