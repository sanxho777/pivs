#!/usr/bin/env python3
# ============================================================
# lpr_intel.py
# Public LPR / Flock Safety Deployment Intelligence
# Sourced from Open Records Data Pipelines
# ============================================================
import argparse
import json
import sys
import textwrap
from datetime import datetime
from typing import Optional

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

BANNER = r"""
â–^â–^â•—     â–^â–^â–^â–^â–^â–^â•— â–^â–^â–^â–^â–^â–^â•—     â–^â–^â•—â–^â–^â–^â•—   â–^â–^â•—â–^â–^â–^â–^â–^â–^â–^â–^â•—â–^â–^â–^â–^â–^â–^â–^â•—â–^â–^â•—
â–^â–^â•‘     â–^â–^â•”â•â•â–^â–^â•—â–^â–^â•”â•â•â–^â–^â•—    â–^â–^â•‘â–^â–^â–^â–^â•—  â–^â–^â•‘â•šâ•â•â–^â–^â•”â•â•â•â–^â–^â•”â•â•â•â•â•â–^â–^â•‘
â–^â–^â•‘     â–^â–^â–^â–^â–^â–^â•”â•â–^â–^â–^â–^â–^â–^â•”â•    â–^â–^â•‘â–^â–^â•”â–^â–^â•— â–^â–^â•‘   â–^â–^â•‘   â–^â–^â–^â–^â–^â•—  â–^â–^â•‘
â–^â–^â•‘     â–^â–^â•”â•â•â•â• â–^â–^â•”â•â•â–^â–^â•—    â–^â–^â•‘â–^â–^â•‘â•šâ–^â–^â•—â–^â–^â•‘   â–^â–^â•‘   â–^â–^â•”â•â•â•  â–^â–^â•‘
â–^â–^â–^â–^â–^â–^â–^â•—â–^â–^â•‘     â–^â–^â•‘  â–^â–^â•‘    â–^â–^â•‘â–^â–^â•‘ â•šâ–^â–^â–^â–^â•‘   â–^â–^â•‘   â–^â–^â–^â–^â–^â–^â–^â•—â–^â–^â–^â–^â–^â–^â–^â•—
â•šâ•â•â•â•â•â•â•â•šâ•â•     â•šâ•â•  â•šâ•â•    â•šâ•â•â•šâ•â•  â•šâ•â•â•â•   â•šâ•â•   â•šâ•â•â•â•â•â•â•â•šâ•â•â•â•â•â•â•
"""

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    ),
    "Accept": "application/json",
}

TIMEOUT = 15

# Corrected active repository URL path for the EFF Atlas Dataset
EFF_ATLAS_URL = (
    "https://raw.githubusercontent.com/EFForg/"
    "Atlas-of-Surveillance/master/data/atlas_data.json"
)

LPR_VENDORS = [
    "Flock Safety",
    "Vigilant Solutions",
    "Motorola Solutions",
    "Rekor Systems",
    "OpenALPR",
    "Genetec",
    "Axon",
    "Plate Reader",
    "License Plate Recognition",
    "ALPR",
    "LPR",
]

STATE_MAP = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona",
    "AR": "Arkansas", "CA": "California", "CO": "Colorado",
    "CT": "Connecticut","DE": "Delaware", "FL": "Florida",
    "GA": "Georgia", "HI": "Hawaii", "ID": "Idaho",
    "IL": "Illinois", "IN": "Indiana", "IA": "Iowa",
    "KS": "Kansas", "KY": "Kentucky", "LA": "Louisiana",
    "ME": "Maine", "MD": "Maryland", "MA": "Massachusetts",
    "MI": "Michigan", "MN": "Minnesota", "MS": "Mississippi",
    "MO": "Missouri", "MT": "Montana", "NE": "Nebraska",
    "NV": "Nevada", "NH": "New Hampshire","NJ": "New Jersey",
    "NM": "New Mexico", "NY": "New York", "NC": "North Carolina",
    "ND": "North Dakota","OH": "Ohio", "OK": "Oklahoma",
    "OR": "Oregon", "PA": "Pennsylvania","RI": "Rhode Island",
    "SC": "South Carolina","SD": "South Dakota","TN": "Tennessee",
    "TX": "Texas", "UT": "Utah", "VT": "Vermont",
    "VA": "Virginia", "WA": "Washington", "WV": "West Virginia",
    "WI": "Wisconsin", "WY": "Wyoming", "DC": "District of Columbia",
}

def safe_get(url: str, params=None, headers=None, timeout: int = TIMEOUT) -> Optional[requests.Response]:
    try:
        h = {**HEADERS, **(headers or {})}
        return requests.get(url, params=params, headers=h, timeout=timeout)
    except requests.RequestException:
        return None

def safe_post(url: str, payload: dict, timeout: int = TIMEOUT) -> Optional[requests.Response]:
    try:
        return requests.post(url, json=payload, headers=HEADERS, timeout=timeout)
    except requests.RequestException:
        return None

def print_section(title: str) -> None:
    console.print(f"\n [bold cyan]â”€â”€ {title}[/bold cyan]")

def print_table(rows: list, headers: list, title: str = "") -> None:
    t = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        padding=(0, 1),
        title=title if title else None,
    )
    for h in headers:
        t.add_column(h, style="white", overflow="fold")
    for row in rows:
        t.add_row(*[str(c) for c in row])
    console.print(t)

# â”€â”€ Module 1: EFF Atlas of Surveillance
def query_eff_atlas(city: str, state: str, state_full: str) -> None:
    print_section("EFF Atlas of Surveillance")
    console.print(" [dim]Fetching public dataset from GitHub...[/dim]")

    resp = safe_get(EFF_ATLAS_URL, timeout=20)
    if not resp or resp.status_code != 200:
        console.print(" [red]! Could not fetch EFF Atlas dataset[/red]")
        return

    try:
        raw_json = resp.json()
        records = raw_json if isinstance(raw_json, list) else raw_json.get("records", [])
    except ValueError:
        console.print(" [red]! EFF Atlas: JSON parse error[/red]")
        return

    city_lower = city.lower().strip()
    state_lower = state_full.lower().strip()
    abbr_lower = state.lower().strip()

    matches = []
    for record in records:
        if not isinstance(record, dict):
            continue
            
        rec_city = str(record.get("City", record.get("city", ""))).lower()
        rec_state = str(record.get("State", record.get("state", ""))).lower()
        rec_agency = str(record.get("Agency", record.get("agency", ""))).lower()
        rec_tech = str(record.get("Technology", record.get("technology", ""))).lower()

        city_match = city_lower in rec_city or rec_city in city_lower
        state_match = (state_lower in rec_state or abbr_lower in rec_state or rec_state in state_lower)

        if city_match or (state_match and any(
            v.lower() in rec_tech or v.lower() in rec_agency
            for v in ["alpr", "lpr", "flock", "plate", "vigilant"]
        )):
            matches.append(record)

    if not matches:
        console.print(f" [dim]No EFF Atlas entries found for {city}, {state}.[/dim]")
        console.print(f" [dim]Browse full atlas: https://atlasofsurveillance.org/search?q={city}[/dim]")
        return

    console.print(f" [bold green]âœ“ {len(matches)} deployment(s) found in EFF Atlas[/bold green]")

    rows = []
    for r in matches:
        rows.append([
            r.get("Agency", r.get("agency", "â€”")),
            r.get("Technology", r.get("technology", "â€”")),
            r.get("City", r.get("city", "â€”")),
            r.get("State", r.get("state", "â€”")),
            str(r.get("Year", r.get("year", "â€”"))),
            str(r.get("Source", r.get("source", "â€”")))[:50],
        ])

    print_table(rows, ["Agency", "Technology", "City", "State", "Year", "Source"])

# â”€â”€ Module 2: USASpending.gov Federal Contracts
def query_usaspending(city: str, state: str, state_full: str) -> None:
    print_section("USASpending.gov â€” Federal Contract Records")
    console.print(" [dim]Querying federal contract database (no API key required)...[/dim]")

    all_rows = []

    for vendor in ["Flock Safety", "Vigilant Solutions", "Rekor Systems", "OpenALPR"]:
        payload = {
            "filters": {
                "keywords": [vendor],
                "place_of_performance_locations": [
                    {"country": "USA", "state": state.upper()}
                ],
                "award_type_codes": ["A", "B", "C", "D"],
            },
            "fields": [
                "Award ID",
                "Recipient Name",
                "Award Amount",
                "Place of Performance City Name",
                "Place of Performance State Code",
                "Action Date",
                "Description",
                "awarding_agency"
            ],
            "page": 1,
            "limit": 25,
            "sort": "Award Amount",
            "order": "desc",
        }

        resp = safe_post(
            "https://api.usaspending.gov/api/v2/search/spending_by_award/",
            payload,
        )

        if not resp or resp.status_code != 200:
            continue

        try:
            data = resp.json()
        except ValueError:
            continue

        results = data.get("results", [])
        if not results:
            continue

        for r in results:
            if r is None or not isinstance(r, dict):
                continue
                
            amount = r.get("Award Amount", 0) or 0
            rec_city = r.get("Place of Performance City Name", "")
            rec_state = r.get("Place of Performance State Code", "")
            desc = r.get("Description", "")[:60]
            date = r.get("Action Date", "")
            award_id = r.get("Award ID", "")

            agency_name = ""
            awarding_agency_obj = r.get("awarding_agency")
            if isinstance(awarding_agency_obj, dict):
                toptier_obj = awarding_agency_obj.get("toptier_agency")
                if isinstance(toptier_obj, dict):
                    agency_name = toptier_obj.get("name", "")

            if not agency_name:
                agency_name = r.get("Awarding Agency Name", "") or "Unknown Federal Agency"

            agency = str(agency_name)[:40]

            all_rows.append([
                vendor,
                award_id,
                f"${amount:,.0f}",
                rec_city,
                rec_state,
                date[:10] if date else "â€”",
                agency,
                desc,
            ])

    if not all_rows:
        console.print(f" [dim]No federal contracts found for LPR vendors in {state_full}.[/dim]")
    else:
        console.print(f" [bold green]âœ“ {len(all_rows)} contract record(s) found[/bold green]")
        print_table(
            all_rows,
            ["Vendor", "Award ID", "Amount", "City", "State", "Date", "Agency", "Description"],
        )

# â”€â”€ Module 3: MuckRock FOIA Database
def query_muckrock(city: str, state: str, state_full: str) -> None:
    print_section("MuckRock â€” Public FOIA Records")
    console.print(" [dim]Searching public FOIA request database...[/dim]")

    queries = [
        f"flock safety {city}",
        f"license plate reader {city} {state}",
    ]

    all_results = []

    for q in queries:
        resp = safe_get(
            "https://www.muckrock.com/foi/list/",
            params={"q": q, "format": "json"},
            timeout=20,
        )
        if not resp or resp.status_code != 200:
            continue

        try:
            data = resp.json()
            items = data.get("results", []) if isinstance(data, dict) else []
            for item in items[:8]:
                if not isinstance(item, dict):
                    continue
                agency_obj = item.get("agency", {})
                agency_name = agency_obj.get("name", "â€”") if isinstance(agency_obj, dict) else "â€”"
                all_results.append({
                    "title": item.get("title", "")[:80],
                    "url": item.get("absolute_url", ""),
                    "status": item.get("status", "â€”"),
                    "agency": str(agency_name)[:40],
                })
        except ValueError:
            try:
                soup = BeautifulSoup(resp.text, "lxml")
                divs = soup.find_all("div", class_=lambda c: c and "result" in c.lower())
                for item in divs[:8]:
                    title_el = item.find(["h2", "h3", "a"])
                    link_el = item.find("a", href=True)
                    if title_el and link_el:
                        all_results.append({
                            "title": title_el.get_text(strip=True)[:80],
                            "url": "https://www.muckrock.com" + link_el["href"] if link_el["href"].startswith("/") else link_el["href"],
                            "status": "â€”",
                            "agency": "â€”",
                        })
            except Exception:
                pass

    seen = set()
    dedup = []
    for r in all_results:
        if r["url"] not in seen:
            seen.add(r["url"])
            dedup.append(r)

    if not dedup:
        console.print(" [dim]No MuckRock results retrieved automatically â€” search manually below.[/dim]")
    else:
        console.print(f" [bold green]âœ“ {len(dedup)} FOIA record(s) found[/bold green]")
        rows = [[r["title"], r["status"], r["agency"], r["url"]] for r in dedup]
        print_table(rows, ["Title", "Status", "Agency", "URL"])

    console.print("\n [dim]MuckRock manual searches:[/dim]")
    city_enc = city.replace(' ', '+')
    console.print(f"  [dim]https://www.muckrock.com/foi/list/?q=flock+safety+{city_enc}[/dim]")

# â”€â”€ Module 4: Public News Search Dorks
def generate_news_dorks(city: str, state: str, state_full: str) -> None:
    print_section("News & Public Record Search Dorks")
    city_enc = city.replace(" ", "+")
    state_enc = state_full.replace(" ", "+")

    dorks = [
        ("Flock Safety Deployment News", f'https://news.google.com/search?q="Flock+Safety"+"{city_enc}"'),
        ("Flock Safety Contract News", f'https://news.google.com/search?q="Flock+Safety"+{state_enc}+contract'),
        ("City Council Minutes", f'https://www.google.com/search?q=site:*.gov+"Flock+Safety"+{city_enc}'),
    ]
    rows = [[label, url] for label, url in dorks]
    print_table(rows, ["Search", "URL"])

# â”€â”€ Module 5: Government Contract Portals
def generate_contract_portals(city: str, state: str, state_full: str) -> None:
    print_section("Government Contract & Procurement Portals")
    city_enc = city.replace(" ", "+")
    portals = [
        ("SAM.gov (Federal Contracts)", "https://sam.gov/search/?keywords=Flock+Safety&index=opp&is_active=true"),
        ("DemandStar", "https://network.demandstar.com/search?searchQuery=flock+safety"),
        (f"{city} City Contracts", f"https://www.google.com/search?q={city_enc}+city+contracts+OR+procurement+%22Flock+Safety%22"),
    ]
    rows = [[label, url] for label, url in portals]
    print_table(rows, ["Portal", "URL"])

# â”€â”€ Module 6: FOIA Request Template Generator
def generate_foia_template(city: str, state: str, state_full: str) -> None:
    print_section("FOIA Request Template")
    today = datetime.now().strftime("%B %d, %Y")
    template = f"""
 Date: {today}
 To: Public Records Officer | {city} Police Department
 Re: Public Records Request â€” Automated License Plate Reader (ALPR) Systems
 
 Pursuant to local open records statutes, I hereby request access to:
 1. All contracts, active agreements, or MOUs with Flock Safety, LLC, or related ALPR vendors.
 2. The aggregate quantity of operational cameras deployed in the city layout.
 3. Data retention schedules and current cross-agency system access logs.
    """
    console.print(Panel(template.strip(), border_style="green", title="Pre-filled Open Records Template"))

# â”€â”€ Module 7: Known Flock Coverage Indicators
def known_flock_indicators(city: str, state: str, state_full: str) -> None:
    print_section("Flock Safety Physical Identification")
    physical = [
        ["Camera Housing", "White rectangular enclosure, ~12\"Ã—8\"Ã—4\""],
        ["Mounting Architecture", "Pole-mounted alignment infrastructure, ~10â€“15 ft high"],
        ["Power footprint", "Solar panel array configurations or hardline AC drops"],
    ]
    print_table(physical, ["Attribute", "Detail"])

# â”€â”€ Module 8: Export
def export_report(city: str, state: str, state_full: str, path: str) -> None:
    data = {
        "query": {"city": city, "state_abbr": state, "state_full": state_full, "generated": datetime.now().isoformat()},
        "note": "Sourced entirely via open analytics parsing endpoints.",
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"\n [green]âœ“ Report metadata exported â†’ {path}[/green]")

def main() -> None:
    parser = argparse.ArgumentParser(description="LPR Intel â€” public LPR/Flock deployment intelligence")
    parser.add_argument("city", nargs="?", help="City name")
    parser.add_argument("state", nargs="?", help="State abbreviation (e.g. CA, TX, FL)")
    parser.add_argument("--json", metavar="FILE", help="Export report metadata as JSON")
    parser.add_argument("--foia-only", action="store_true", help="Only output FOIA template")
    args = parser.parse_args()

    console.print(f"[cyan]{BANNER}[/cyan]")
    
    city = args.city
    state = args.state

    if not city:
        city = Prompt.ask(" [bold cyan]City[/bold cyan]").strip()
    if not state:
        state = Prompt.ask(" [bold cyan]State abbreviation[/bold cyan]").strip().upper()

    city = city.strip().title()
    state = state.upper()
    state_full = STATE_MAP.get(state, state)

    header = Text()
    header.append("Target: ", style="dim")
    header.append(f"{city}, {state_full} ({state})", style="bold white")
    console.print(Panel(header, border_style="cyan", padding=(0, 2)))

    if args.foia_only:
        generate_foia_template(city, state, state_full)
        return

    query_eff_atlas(city, state, state_full)
    query_usaspending(city, state, state_full)
    query_muckrock(city, state, state_full)
    generate_news_dorks(city, state, state_full)
    generate_contract_portals(city, state, state_full)
    known_flock_indicators(city, state, state_full)
    generate_foia_template(city, state, state_full)

    if args.json:
        export_report(city, state, state_full, args.json)

    console.print("\n [bold green]â”€â”€ Complete[/bold green] [dim]All data parsed successfully.[/dim]\n")

if __name__ == "__main__":
    main()
