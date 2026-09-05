# ============================================================
# username_checker.py
# — Async WhatsMyName engine
# ============================================================
import asyncio
import ssl
from dataclasses import dataclass
from typing import List, Optional, Dict, Any

import aiohttp
from rich.console  import Console
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, TimeElapsedColumn, MofNCompleteColumn,
)

console = Console()

# ── Constants ─────────────────────────────────────────────────────────────────
CONCURRENT_LIMIT = 25        # simultaneous open connections
REQUEST_TIMEOUT  = 10        # seconds per request
MAX_RESPONSE_LEN = 1_500_000 # bytes — don't read massive pages into memory


@dataclass
class CheckResult:
    site_name:  str
    username:   str
    url:        str
    status:     str   # "FOUND" | "NOT_FOUND" | "ERROR"
    detail:     str   # extra context


# ── Core async checker ────────────────────────────────────────────────────────
async def _check_one(
    session:   aiohttp.ClientSession,
    site:      Dict[str, Any],
    username:  str,
    semaphore: asyncio.Semaphore,
) -> Optional[CheckResult]:
    """
    Check a single site for a single username.
    Returns a CheckResult only on FOUND; None otherwise.
    """
    uri_template = site.get("uri_check", "")
    if not uri_template or "{account}" not in uri_template:
        return None

    url      = uri_template.replace("{account}", username)
    e_code   = site.get("e_code",   200)
    e_string = site.get("e_string", "")
    m_string = site.get("m_string", "")

    async with semaphore:
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                allow_redirects=True,
                ssl=False,          # skip SSL verification — many sites have quirky certs
            ) as resp:

                if resp.status != e_code:
                    return None

                # Read body only if we need string matching
                body = ""
                if e_string or m_string:
                    raw = await resp.content.read(MAX_RESPONSE_LEN)
                    try:
                        body = raw.decode("utf-8", errors="replace")
                    except Exception:
                        return None

                # Must contain e_string (if specified)
                if e_string and e_string not in body:
                    return None

                # Must NOT contain m_string (if specified) — false-positive guard
                if m_string and m_string in body:
                    return None

                return CheckResult(
                    site_name = site.get("name", "Unknown"),
                    username  = username,
                    url       = url,
                    status    = "FOUND",
                    detail    = f"HTTP {resp.status}",
                )

        except asyncio.TimeoutError:
            return None
        except aiohttp.ClientError:
            return None
        except Exception:
            return None


async def _run_batch(
    sites:     List[Dict[str, Any]],
    usernames: List[str],
    show_progress: bool = True,
) -> List[CheckResult]:
    """
    Check every (site × username) combination concurrently.
    Returns a list of confirmed hits only.
    """
    semaphore = asyncio.Semaphore(CONCURRENT_LIMIT)
    tasks     = []

    # Flatten the cartesian product into a task list
    pairs = [(site, username) for username in usernames for site in sites]
    total = len(pairs)

    connector = aiohttp.TCPConnector(
        limit=CONCURRENT_LIMIT + 10,
        ttl_dns_cache=300,
        ssl=False,
    )
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0 Safari/537.36"
        )
    }

    hits: List[CheckResult] = []

    async with aiohttp.ClientSession(
        connector=connector,
        headers=headers,
    ) as session:

        tasks = [
            _check_one(session, site, username, semaphore)
            for site, username in pairs
        ]

        if show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]Checking[/bold cyan]"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task_id = progress.add_task("", total=total)

                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    if result:
                        hits.append(result)
                    progress.advance(task_id)
        else:
            results = await asyncio.gather(*tasks, return_exceptions=False)
            hits = [r for r in results if r is not None]

    return hits


def run_username_check(
    sites:     List[Dict[str, Any]],
    usernames: List[str],
    show_progress: bool = True,
) -> List[CheckResult]:
    """
    Synchronous entry point — wraps the async engine so callers
    don't need to manage their own event loop.
    """
    return asyncio.run(_run_batch(sites, usernames, show_progress))
