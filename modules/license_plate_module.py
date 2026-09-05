# ============================================================
# modules/license_plate_module.py
# ============================================================
import re
from typing import Optional, List, Tuple
from urllib.parse import quote

from bs4 import BeautifulSoup

from .base import BaseModule, ResultSet
from utils import safe_get

_SCRAPE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

# US state plate format patterns (regex, state name, common format description)
_STATE_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"^[0-9][A-Z]{3}[0-9]{3}$"),         "California",      "1ABC234"),
    (re.compile(r"^[A-Z]{3}[0-9]{4}$"),               "Texas/New York",  "ABC1234"),
    (re.compile(r"^[A-Z]{3}[0-9]{3}[A-Z]$"),          "Florida",         "ABC123D"),
    (re.compile(r"^[A-Z]{2}[0-9]{3}[A-Z]{2}$"),       "Ohio",            "AB123CD"),
    (re.compile(r"^[0-9]{3}[A-Z]{3}$"),               "Michigan",        "123ABC"),
    (re.compile(r"^[A-Z]{2}[0-9]{5}$"),               "Pennsylvania",    "AB12345"),
    (re.compile(r"^[0-9]{3}[A-Z]{2}[0-9]{2}$"),       "Illinois",        "123AB45"),
    (re.compile(r"^[A-Z]{3}[0-9]{3}$"),               "Georgia/Nevada",  "ABC123"),
    (re.compile(r"^[0-9]{2}[A-Z]{2}[0-9]{3}$"),       "Tennessee",       "12AB345"),
    (re.compile(r"^[A-Z]{2}[0-9]{4}[A-Z]$"),          "North Carolina",  "AB1234C"),
    (re.compile(r"^[0-9][A-Z]{2}[0-9]{4}$"),          "Arizona",         "1AB2345"),
    (re.compile(r"^[A-Z]{3}[0-9]{2}[A-Z]{2}$"),       "Colorado",        "ABC12DE"),
    (re.compile(r"^[A-Z]{1}[0-9]{6}$"),               "Washington DC",   "A123456"),
    (re.compile(r"^[0-9]{3}[A-Z]{3}$"),               "Oregon",          "123ABC"),
    (re.compile(r"^[A-Z]{2}[0-9]{3}[A-Z]{1}[0-9]{1}$"),"Indiana",       "AB123C4"),
    (re.compile(r"^[0-9]{3}[A-Z]{2}[0-9]{3}$"),       "Minnesota",       "123AB456"),
    (re.compile(r"^[A-Z]{2}[0-9]{2}[A-Z]{3}$"),       "Wisconsin",       "AB12CDE"),
    (re.compile(r"^[A-Z]{3}[0-9]{4}$"),               "Missouri",        "ABC1234"),
    (re.compile(r"^[A-Z][0-9]{6}$"),                  "Massachusetts",   "A123456"),
    (re.compile(r"^[0-9]{3}[A-Z]{2}[0-9]{2}$"),       "Virginia",        "123AB45"),
]

# Non-US plate patterns
_INTL_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"^[A-Z]{2}[0-9]{2}\s?[A-Z]{3}$"),     "United Kingdom"),
    (re.compile(r"^[A-Z]{1,2}[0-9]{1,4}[A-Z]{1,3}$"),  "Germany"),
    (re.compile(r"^[A-Z]{1,3}[0-9]{3}[A-Z]{2}$"),       "France"),
    (re.compile(r"^[A-Z]{2}[0-9]{3}[A-Z]{2}$"),         "Spain / Italy"),
    (re.compile(r"^[0-9]{3}[A-Z]{3}$"),                 "Mexico"),
    (re.compile(r"^[A-Z]{3}[0-9]{4}$"),                 "Canada (various)"),
    (re.compile(r"^[0-9]{3}[0-9]{2}[A-Z]{2}$"),         "Netherlands"),
    (re.compile(r"^[A-Z]{2}[0-9]{2}[A-Z]{2}[0-9]{2}$"), "Australia (various)"),
]


def _clean_plate(raw: str) -> str:
    """Normalize plate: uppercase, strip spaces/hyphens for pattern matching."""
    return re.sub(r"[\s\-\.]", "", raw.strip().upper())


def _identify_state(plate: str) -> List[str]:
    clean = _clean_plate(plate)
    matches = []
    for pattern, state, fmt in _STATE_PATTERNS:
        if pattern.match(clean):
            matches.append(f"{state} ({fmt})")
    for pattern, country in _INTL_PATTERNS:
        if pattern.match(clean):
            matches.append(country)
    return matches if matches else ["Could not determine — manual verification needed"]


class LicensePlateModule(BaseModule):

    @property
    def name(self) -> str:
        return "License Plate Intelligence"

    def run(self, pivot: str, results: ResultSet) -> None:
        plate = pivot.strip().upper()
        clean = _clean_plate(plate)

        results.add("Plate", "Input",     plate,  "Local Parse")
        results.add("Plate", "Normalized", clean,  "Local Parse")
        results.add("Plate", "Length",    str(len(clean)), "Local Parse")

        self._identify_origin(plate, clean, results)
        self._generate_lookup_pivots(plate, clean, results)
        self._generate_search_dorks(plate, clean, results)

    def enrich(self, pivot: str, results: ResultSet) -> None:
        plate = pivot.strip().upper()
        clean = _clean_plate(plate)

        self._enrich_platesmania(plate, clean, results)
        self._enrich_findbyplate(plate, clean, results)
        self._enrich_social_sightings(plate, clean, results)

    # ── run() methods ─────────────────────────────────────────

    def _identify_origin(self, plate: str, clean: str,
                          results: ResultSet) -> None:
        candidates = _identify_state(clean)

        results.add("Origin Analysis", "Possible State / Region",
                    " | ".join(candidates), "Local Pattern Match")

        # Character composition analysis
        letters = sum(1 for c in clean if c.isalpha())
        digits  = sum(1 for c in clean if c.isdigit())
        results.add("Origin Analysis", "Letters",
                    str(letters), "Local Parse")
        results.add("Origin Analysis", "Digits",
                    str(digits), "Local Parse")

        # Detect vanity plate (all letters, or recognizable word)
        if digits == 0:
            results.add("Origin Analysis", "Vanity Plate",
                        "Possible — no digits detected", "Local Parse")
        elif letters == 0:
            results.add("Origin Analysis", "Numeric Only",
                        "Fleet, trailer, or temporary plate possible",
                        "Local Parse")

        # Detect temporary / paper plate patterns
        if re.match(r"^T\d{6,}$", clean) or re.match(r"^TEMP", clean):
            results.add("Origin Analysis", "Plate Type",
                        "Temporary / Paper plate likely", "Local Parse")

    def _generate_lookup_pivots(self, plate: str, clean: str,
                                 results: ResultSet) -> None:
        enc = quote(plate)

        lookups = [
            ("VehicleHistory",
             f"https://www.vehiclehistory.com/license-plate-lookup/?plate={enc}"),
            ("FaxVIN Plate Lookup",
             f"https://www.faxvin.com/license-plate-lookup/result?plate={enc}&state="),
            ("FindByPlate",
             f"https://www.findbyplate.com/US/{enc}/"),
            ("PlateSearch",
             f"https://www.platesearch.com/?plate={enc}"),
            ("AutoCheck Plate",
             f"https://www.autocheck.com/vehiclehistory/plate/?plate={enc}&state="),
            ("Platesmania",
             f"https://www.platesmania.com/search/?q={enc}"),
            ("OpenDMV",
             f"https://opendmv.com/records/license-plate/{enc}"),
            ("LicensePlateData",
             f"https://licenseplatedata.com/search?plate={enc}"),
            ("iSeeCars",
             f"https://www.iseecars.com/license-plate#{enc}"),
            ("DMV.org",
             f"https://www.dmv.org/driver-resources/plate-lookup.php"),
        ]
        for label, url in lookups:
            results.add("Lookup Services", label, url, "Generated")

    def _generate_search_dorks(self, plate: str, clean: str,
                                results: ResultSet) -> None:
        dorks = [
            ("Google",
             f'https://www.google.com/search?q="{plate}"'),
            ("Google Clean",
             f'https://www.google.com/search?q="{clean}"'),
            ("YouTube Dashcam",
             f'https://www.youtube.com/results?search_query="{plate}"+dashcam'),
            ("Reddit",
             f'https://www.reddit.com/search/?q="{plate}"'),
            ("Twitter/X",
             f'https://twitter.com/search?q="{plate}"'),
            ("News",
             f'https://www.google.com/search?q="{plate}"&tbm=nws'),
            ("Facebook",
             f'https://www.facebook.com/search/top?q={quote(plate)}'),
            ("Nextdoor Dork",
             f'https://www.google.com/search?q=site:nextdoor.com+"{plate}"'),
            ("Forums Dork",
             f'https://www.google.com/search?q="{plate}"+forum'),
            ("Pastebin Dork",
             f'https://www.google.com/search?q=site:pastebin.com+"{plate}"'),
            ("Wayback Machine",
             f"https://web.archive.org/web/*/{clean}"),
        ]
        for label, url in dorks:
            results.add("Search Dorks", label, url, "Generated")

    # ── enrich() methods ──────────────────────────────────────

    def _enrich_platesmania(self, plate: str, clean: str,
                             results: ResultSet) -> None:
        resp = safe_get(
            "https://www.platesmania.com/search/",
            params={"q": clean},
            headers=_SCRAPE_HEADERS,
            timeout=15,
        )
        if not resp or resp.status_code != 200:
            results.add_error("Platesmania: no response")
            return

        try:
            soup = BeautifulSoup(resp.text, "lxml")
        except Exception:
            soup = BeautifulSoup(resp.text, "html.parser")

        src = "platesmania.com"

        # Look for plate result cards
        cards = soup.find_all("div", class_=re.compile(r"gal|plate|card",
                                                        re.IGNORECASE))
        if not cards:
            # Try broader search
            cards = soup.find_all("a", href=re.compile(r"/\w{2,}/\d+"))

        hits = 0
        for card in cards[:10]:
            text = card.get_text(strip=True)
            link = card.get("href", "")
            if clean.lower() in text.lower() or clean in str(card):
                if link and not link.startswith("http"):
                    link = f"https://www.platesmania.com{link}"
                results.add("Platesmania Sightings",
                            f"Sighting {hits + 1}",
                            f"{text[:80]} — {link}" if link else text[:80],
                            src)
                hits += 1

        if hits == 0:
            # Check result count in page text
            page_text = soup.get_text()
            count_match = re.search(r"(\d+)\s+(?:result|photo|match)",
                                    page_text, re.IGNORECASE)
            if count_match:
                results.add("Platesmania Sightings", "Results Found",
                            count_match.group(0), src)
            else:
                results.add("Platesmania Sightings", "Result",
                            "No sightings found or page structure changed",
                            src)

        results.add("Platesmania Sightings", "Search URL",
                    f"https://www.platesmania.com/search/?q={clean}",
                    src)

    def _enrich_findbyplate(self, plate: str, clean: str,
                             results: ResultSet) -> None:
        resp = safe_get(
            f"https://www.findbyplate.com/US/{clean}/",
            headers=_SCRAPE_HEADERS,
            timeout=15,
        )
        if not resp or resp.status_code not in (200, 301, 302):
            results.add_error(
                f"FindByPlate: HTTP {resp.status_code if resp else 'no response'}"
            )
            return

        try:
            soup = BeautifulSoup(resp.text, "lxml")
        except Exception:
            soup = BeautifulSoup(resp.text, "html.parser")

        src = "findbyplate.com"

        # Extract vehicle info if present
        for tag in soup.find_all(["h1", "h2", "h3", "p", "td", "li"]):
            text = tag.get_text(strip=True)
            if not text or len(text) < 4 or len(text) > 200:
                continue
            for keyword in ["make", "model", "year", "vin",
                            "color", "state", "registered"]:
                if keyword in text.lower():
                    results.add("FindByPlate", keyword.capitalize(),
                                text[:150], src)
                    break

        # Meta description often has vehicle summary
        meta = soup.find("meta", attrs={"name": "description"})
        if meta and meta.get("content"):
            content = meta["content"].strip()
            if clean.lower() in content.lower() or plate.lower() in content.lower():
                results.add("FindByPlate", "Page Description",
                            content[:200], src)

        results.add("FindByPlate", "Direct URL",
                    f"https://www.findbyplate.com/US/{clean}/",
                    src)

    def _enrich_social_sightings(self, plate: str, clean: str,
                                  results: ResultSet) -> None:
        # Generate dashcam / sighting specific pivots
        sighting_pivots = [
            ("Reddit r/Roadcam",
             f'https://www.reddit.com/r/roadcam/search/?q="{plate}"'),
            ("Reddit r/IdiotsInCars",
             f'https://www.reddit.com/r/IdiotsInCars/search/?q="{plate}"'),
            ("YouTube",
             f'https://www.youtube.com/results?search_query="{plate}"'),
            ("TikTok",
             f'https://www.tiktok.com/search?q={quote(plate)}'),
            ("Instagram",
             f'https://www.google.com/search?q=site:instagram.com+"{plate}"'),
            ("Dashcam Forum",
             f'https://www.google.com/search?q="{plate}"+dashcam+footage'),
            ("NextDoor Sighting",
             f'https://www.google.com/search?q=site:nextdoor.com+"{plate}"'),
            ("Crime Report Check",
             f'https://www.google.com/search?q="{plate}"+crime+report+OR+police'),
        ]
        for label, url in sighting_pivots:
            results.add("Social Sightings", label, url, "Generated")
