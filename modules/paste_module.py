# ============================================================
# modules/paste_module.py
# ============================================================
import time
from typing import List

from .base import BaseModule, ResultSet
from utils import safe_get, safe_json


class PasteModule:
    """
    Not a standalone pivot — called by other modules to sweep
    paste sites for mentions of an email or username.
    """

    def sweep(self, query: str, results: ResultSet,
              label: str = "Paste Sites") -> None:
        self._psbdmp(query, results, label)
        self._github_code_search(query, results, label)
        self._grep_app(query, results, label)
        self._generate_manual_dorks(query, results, label)

    # ── psbdmp.ws — free pastebin search API ──────────────────
    def _psbdmp(self, query: str, results: ResultSet,
                label: str) -> None:
        resp = safe_get(
            f"https://psbdmp.ws/api/search/{query}",
            timeout=15,
        )
        if not resp or resp.status_code != 200:
            results.add_error(f"psbdmp: no response for '{query}'")
            return

        try:
            data = resp.json()
        except ValueError:
            return

        pastes = data if isinstance(data, list) else data.get("data", [])
        if not pastes:
            results.add(label, "Pastebin (psbdmp)", "No results found",
                        "psbdmp.ws")
            return

        results.add(label, "Pastebin Hits", str(len(pastes)), "psbdmp.ws")
        for paste in pastes[:15]:
            paste_id   = paste.get("id", "")
            paste_text = paste.get("text", "")[:120].replace("\n", " ")
            if paste_id:
                results.add(
                    label,
                    f"Pastebin/{paste_id}",
                    f"{paste_text}... — https://pastebin.com/{paste_id}",
                    "psbdmp.ws",
                )

    # ── GitHub code search (unauthenticated, 10 req/min) ──────
    def _github_code_search(self, query: str, results: ResultSet,
                             label: str) -> None:
        resp = safe_get(
            "https://api.github.com/search/code",
            params={"q": query, "per_page": 10},
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=15,
        )
        if not resp:
            return

        if resp.status_code == 403:
            results.add(label, "GitHub Code Search",
                        "Rate limited — try again in 60s", "api.github.com")
            return

        try:
            data = resp.json()
        except ValueError:
            return

        items = data.get("items", [])
        total = data.get("total_count", 0)

        if total == 0:
            results.add(label, "GitHub Code Search",
                        "No results", "api.github.com")
            return

        results.add(label, "GitHub Total Hits",
                    str(total), "api.github.com")

        for item in items[:10]:
            repo = item.get("repository", {}).get("full_name", "")
            path = item.get("path", "")
            url  = item.get("html_url", "")
            results.add(label, f"GitHub: {repo}/{path}",
                        url, "api.github.com")

        time.sleep(6)  # respect 10 req/min unauthenticated cap

    # ── grep.app — code search across public repos ────────────
    def _grep_app(self, query: str, results: ResultSet,
                  label: str) -> None:
        resp = safe_get(
            "https://grep.app/api/search",
            params={"q": query, "case": "true"},
            timeout=15,
        )
        if not resp or resp.status_code != 200:
            return

        try:
            data = resp.json()
        except ValueError:
            return

        hits  = data.get("hits", {})
        total = hits.get("total", {}).get("value", 0)

        if total == 0:
            results.add(label, "grep.app", "No results", "grep.app")
            return

        results.add(label, "grep.app Total Hits", str(total), "grep.app")

        for hit in hits.get("hits", [])[:8]:
            repo    = hit.get("repo", {}).get("raw", "")
            file_   = hit.get("path", {}).get("raw", "")
            results.add(
                label,
                f"grep.app: {repo}/{file_}",
                f"https://grep.app/search?q={query}",
                "grep.app",
            )

    # ── Manual dork links for human follow-up ─────────────────
    def _generate_manual_dorks(self, query: str, results: ResultSet,
                                label: str) -> None:
        enc = query.replace("@", "%40").replace(" ", "+")
        dorks = [
            ("Pastebin Dork",
             f'https://www.google.com/search?q=site:pastebin.com+"{query}"'),
            ("Ghostbin Dork",
             f'https://www.google.com/search?q=site:ghostbin.com+"{query}"'),
            ("Rentry Dork",
             f'https://www.google.com/search?q=site:rentry.co+"{query}"'),
            ("Paste.ee Dork",
             f'https://www.google.com/search?q=site:paste.ee+"{query}"'),
            ("Hastebin Dork",
             f'https://www.google.com/search?q=site:hastebin.com+"{query}"'),
        ]
        for name, url in dorks:
            results.add(label, name, url, "Generated")
