# ============================================================
# modules/vin_module.py
# ============================================================
from typing import Optional

from .base import BaseModule, ResultSet
from utils import safe_get, safe_json

_NHTSA_DECODE_URL     = "https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVin/{vin}?format=json"
_NHTSA_RECALLS_URL    = "https://api.nhtsa.gov/recalls/recallsByVehicle"
_NHTSA_COMPLAINTS_URL = "https://api.nhtsa.gov/complaints/complaintsByVehicle"

# VIN position 10 → model year
_YEAR_MAP = {
    "A": 1980, "B": 1981, "C": 1982, "D": 1983, "E": 1984,
    "F": 1985, "G": 1986, "H": 1987, "J": 1988, "K": 1989,
    "L": 1990, "M": 1991, "N": 1992, "P": 1993, "R": 1994,
    "S": 1995, "T": 1996, "V": 1997, "W": 1998, "X": 1999,
    "Y": 2000, "1": 2001, "2": 2002, "3": 2003, "4": 2004,
    "5": 2005, "6": 2006, "7": 2007, "8": 2008, "9": 2009,
    # Second cycle (2010+)
    "A2": 2010, "B2": 2011, "C2": 2012, "D2": 2013, "E2": 2014,
    "F2": 2015, "G2": 2016, "H2": 2017, "J2": 2018, "K2": 2019,
    "L2": 2020, "M2": 2021, "N2": 2022, "P2": 2023, "R2": 2024,
}

# WMI first character → country
_COUNTRY_MAP = {
    "1": "United States", "4": "United States", "5": "United States",
    "2": "Canada",
    "3": "Mexico",
    "J": "Japan",
    "K": "South Korea",
    "L": "China",
    "S": "United Kingdom",
    "V": "France / Spain",
    "W": "Germany",
    "Z": "Italy",
    "9": "Brazil",
    "6": "Australia",
    "7": "New Zealand",
    "8": "Argentina",
}

# Check digit transliteration
_TRANSLIT = {
    "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
    "J": 1, "K": 2, "L": 3, "M": 4, "N": 5,          "P": 7,
    "R": 9, "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8,
    "Z": 9,
}
_WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]


def _validate_check_digit(vin: str) -> bool:
    total = 0
    for i, ch in enumerate(vin.upper()):
        if ch.isdigit():
            val = int(ch)
        else:
            val = _TRANSLIT.get(ch, 0)
        total += val * _WEIGHTS[i]
    remainder = total % 11
    expected  = "X" if remainder == 10 else str(remainder)
    return vin[8].upper() == expected


def _decode_year(char: str, vin: str) -> str:
    """
    Model year is ambiguous (cycles every 30 years).
    Use plant code and sequence to hint at which cycle.
    """
    year = _YEAR_MAP.get(char.upper())
    if year is None:
        return "Unknown"
    # Sequence number heuristic — if seq > ~500000, likely newer cycle
    try:
        seq = int(vin[11:17])
        if year <= 2000 and seq > 100000:
            year += 30
    except ValueError:
        pass
    return str(year)


class VINModule(BaseModule):

    @property
    def name(self) -> str:
        return "VIN Intelligence"

    def run(self, pivot: str, results: ResultSet) -> None:
        vin = pivot.strip().upper()
        results.add("VIN", "Input VIN", vin, "Local Parse")

        self._local_decode(vin, results)
        self._nhtsa_decode(vin, results)
        self._generate_pivots(vin, results)

    def enrich(self, pivot: str, results: ResultSet) -> None:
        vin = pivot.strip().upper()

        # Pull make/model/year from already-gathered findings
        make  = self._find_finding(results, "NHTSA Decode", "Make")
        model = self._find_finding(results, "NHTSA Decode", "Model")
        year  = self._find_finding(results, "NHTSA Decode", "Model Year")

        if make and model and year:
            self._nhtsa_recalls(make, model, year, results)
            self._nhtsa_complaints(make, model, year, results)

        self._enrich_theft_check(vin, results)
        self._enrich_history_pivots(vin, make, model, year, results)

    # ── Helpers ───────────────────────────────────────────────

    def _find_finding(self, results: ResultSet,
                      category: str, key: str) -> Optional[str]:
        for f in results.findings:
            if f.category == category and f.key == key:
                return f.value
        return None

    # ── run() methods ─────────────────────────────────────────

    def _local_decode(self, vin: str, results: ResultSet) -> None:
        src = "Local VIN Parse"

        # Length check
        if len(vin) != 17:
            results.add_error(
                f"VIN length invalid: {len(vin)} chars (expected 17)"
            )
            return

        # Check digit validation
        valid_check = _validate_check_digit(vin)
        results.add("VIN Structure", "Check Digit Valid",
                    "Yes" if valid_check else "No — may be invalid or rebuilt",
                    src)

        # WMI (World Manufacturer Identifier)
        wmi = vin[:3]
        results.add("VIN Structure", "WMI", wmi, src)

        country = _COUNTRY_MAP.get(vin[0], "Unknown")
        results.add("VIN Structure", "Country of Manufacture",
                    country, src)

        # VDS (Vehicle Descriptor Section)
        vds = vin[3:9]
        results.add("VIN Structure", "VDS", vds, src)

        # Model year
        year_char = vin[9]
        year      = _decode_year(year_char, vin)
        results.add("VIN Structure", "Model Year (Local)",
                    f"{year} (encoded: '{year_char}')", src)

        # Plant code
        plant = vin[10]
        results.add("VIN Structure", "Assembly Plant Code",
                    plant, src)

        # Production sequence
        seq = vin[11:17]
        results.add("VIN Structure", "Production Sequence",
                    seq, src)

        # VIS (Vehicle Identifier Section)
        vis = vin[9:17]
        results.add("VIN Structure", "VIS", vis, src)

    def _nhtsa_decode(self, vin: str, results: ResultSet) -> None:
        resp = safe_get(
            f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVin/{vin}",
            params={"format": "json"},
            timeout=20,
        )
        data = safe_json(resp)

        if not data:
            results.add_error("NHTSA VIN decode: no response")
            return

        results_list = data.get("Results", [])
        if not results_list:
            results.add_error("NHTSA VIN decode: empty results")
            return

        src = "NHTSA vpic.nhtsa.dot.gov"

        # Fields we care about, in display order
        fields_of_interest = [
            ("Make",                          "Make"),
            ("Model",                         "Model"),
            ("Model Year",                    "Model Year"),
            ("Body Class",                    "Body Class"),
            ("Vehicle Type",                  "Vehicle Type"),
            ("Manufacturer Name",             "Manufacturer Name"),
            ("Plant City",                    "Plant City"),
            ("Plant Country",                 "Plant Country"),
            ("Plant State",                   "Plant State"),
            ("Engine Number of Cylinders",    "Engine Cylinders"),
            ("Displacement (L)",              "Engine Displacement (L)"),
            ("Fuel Type - Primary",           "Fuel Type"),
            ("Drive Type",                    "Drive Type"),
            ("Transmission Style",            "Transmission"),
            ("Transmission Speeds",           "Transmission Speeds"),
            ("Series",                        "Series"),
            ("Trim",                          "Trim"),
            ("Doors",                         "Doors"),
            ("Seats",                         "Seats"),
            ("Gross Vehicle Weight Rating From", "GVWR From"),
            ("Gross Vehicle Weight Rating To",   "GVWR To"),
            ("Base Price ($)",                "Base Price"),
            ("Destination Market",            "Destination Market"),
            ("Safety Rating",                 "Safety Rating"),
            ("ABS",                           "ABS"),
            ("Electronic Stability Control (ESC)", "ESC"),
            ("Airbag Locations Curtain",      "Curtain Airbags"),
            ("Airbag Locations Front",        "Front Airbags"),
            ("Airbag Locations Side",         "Side Airbags"),
            ("NCSA Body Type",                "NCSA Body Type"),
            ("NCSA Make",                     "NCSA Make"),
            ("Brake System Type",             "Brake System"),
            ("Engine Model",                  "Engine Model"),
            ("Engine Brake (hp) From",        "Engine HP From"),
            ("Engine Brake (hp) To",          "Engine HP To"),
            ("Turbo",                         "Turbo"),
            ("Valve Train Design",            "Valve Train"),
            ("Primary Fuel Type",             "Primary Fuel"),
        ]

        # Build lookup dict from NHTSA response
        nhtsa_map = {
            item.get("Variable", ""): item.get("Value", "")
            for item in results_list
        }

        for nhtsa_key, display_label in fields_of_interest:
            val = nhtsa_map.get(nhtsa_key, "")
            if val and val.strip() and val.strip() not in ("None", "Not Applicable", "0"):
                results.add("NHTSA Decode", display_label, val.strip(), src)

        # Error codes from NHTSA
        error_code = nhtsa_map.get("Error Code", "")
        error_text = nhtsa_map.get("Error Text", "")
        if error_code and error_code != "0":
            results.add("NHTSA Decode", "Decode Error Code",
                        error_code, src)
        if error_text and error_text.strip() not in ("", "0 - VIN decoded clean. Check Digit (9th position) is correct"):
            results.add("NHTSA Decode", "Decode Notes",
                        error_text.strip()[:200], src)
        else:
            results.add("NHTSA Decode", "Decode Status",
                        "Clean decode — no errors", src)

    def _generate_pivots(self, vin: str, results: ResultSet) -> None:
        pivots = [
            ("NHTSA VINCheck (Theft)",
             f"https://www.nhtsa.gov/vehicle/"),
            ("NICB VINCheck",
             f"https://www.nicb.org/vincheck"),
            ("NHTSA Safety Ratings",
             f"https://www.nhtsa.gov/vehicle/"),
            ("AutoCheck",
             f"https://www.autocheck.com/vehiclehistory/?vin={vin}"),
            ("Carfax",
             f"https://www.carfax.com/vehicle/{vin}"),
            ("VinAudit",
             f"https://www.vinaudit.com/results?vin={vin}"),
            ("iSeeCars",
             f"https://www.iseecars.com/vin#{vin}"),
            ("VehicleHistory",
             f"https://www.vehiclehistory.com/vin/{vin}"),
            ("FaxVin",
             f"https://www.faxvin.com/vin-check/result?vin={vin}"),
            ("VINSmith",
             f"https://www.vinsmith.net/vin/{vin}"),
            ("Google",
             f'https://www.google.com/search?q="{vin}"'),
        ]
        for label, url in pivots:
            results.add("Research Pivots", label, url, "Generated")

    # ── enrich() methods ──────────────────────────────────────

    def _nhtsa_recalls(self, make: str, model: str,
                       year: str, results: ResultSet) -> None:
        resp = safe_get(
            _NHTSA_RECALLS_URL,
            params={"make": make, "model": model, "modelYear": year},
            timeout=20,
        )
        data = safe_json(resp)

        if not data:
            results.add_error("NHTSA recalls: no response")
            return

        recalls   = data.get("results", [])
        src       = "api.nhtsa.gov/recalls"

        results.add("NHTSA Recalls", "Total Recalls Found",
                    str(len(recalls)), src)

        for r in recalls[:15]:
            campaign  = r.get("NHTSACampaignNumber", "")
            component = r.get("Component", "")
            summary   = r.get("Summary", "")[:150]
            remedy    = r.get("Remedy", "")[:100]
            date      = r.get("ReportReceivedDate", "")

            if campaign:
                results.add("NHTSA Recalls",
                            f"Campaign {campaign}",
                            f"Component: {component} | Date: {date}",
                            src)
            if summary:
                results.add("NHTSA Recalls",
                            f"Summary ({campaign})",
                            summary, src)
            if remedy:
                results.add("NHTSA Recalls",
                            f"Remedy ({campaign})",
                            remedy, src)

    def _nhtsa_complaints(self, make: str, model: str,
                          year: str, results: ResultSet) -> None:
        resp = safe_get(
            _NHTSA_COMPLAINTS_URL,
            params={"make": make, "model": model, "modelYear": year},
            timeout=20,
        )
        data = safe_json(resp)

        if not data:
            results.add_error("NHTSA complaints: no response")
            return

        complaints = data.get("results", [])
        src        = "api.nhtsa.gov/complaints"

        results.add("NHTSA Complaints", "Total Complaints Found",
                    str(len(complaints)), src)

        # Group by component
        component_counts: dict = {}
        for c in complaints:
            comp = c.get("components", "Unknown")
            component_counts[comp] = component_counts.get(comp, 0) + 1

        for comp, count in sorted(
            component_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]:
            results.add("NHTSA Complaints", f"Component: {comp}",
                        f"{count} complaint(s)", src)

        # Show most recent 5 complaint summaries
        for c in complaints[:5]:
            summary = c.get("summary", "")[:150]
            date    = c.get("dateOfIncident", "")
            comp    = c.get("components", "")
            if summary:
                results.add("NHTSA Complaints",
                            f"Incident ({date})",
                            f"[{comp}] {summary}", src)

    def _enrich_theft_check(self, vin: str, results: ResultSet) -> None:
        # NICB VINCheck — pivot only (requires CAPTCHA for actual check)
        results.add("Theft Check", "NICB VINCheck",
                    f"https://www.nicb.org/vincheck (manual entry: {vin})",
                    "Generated")
        results.add("Theft Check", "NHTSA Stolen Vehicle",
                    f'https://www.google.com/search?q="{vin}"+stolen+vehicle',
                    "Generated")
        results.add("Theft Check", "NCIC Check Pivot",
                    f'https://www.google.com/search?q="{vin}"+NCIC',
                    "Generated")

    def _enrich_history_pivots(self, vin: str,
                                make: Optional[str],
                                model: Optional[str],
                                year: Optional[str],
                                results: ResultSet) -> None:
        vehicle_str = f"{year} {make} {model}" if all([year, make, model]) \
                      else vin

        extra_pivots = [
            ("Auction History",
             f'https://www.google.com/search?q="{vin}"+auction'),
            ("Insurance Total Loss",
             f'https://www.google.com/search?q="{vin}"+total+loss'),
            ("Fleet Records",
             f'https://www.google.com/search?q="{vin}"+fleet'),
            ("Lien / Title Check",
             f'https://www.google.com/search?q="{vin}"+lien+title'),
            ("Social Media Sightings",
             f'https://www.google.com/search?q="{vin}"'),
            ("Owner Forums",
             f'https://www.google.com/search?q="{vehicle_str}"+owner+forum'),
            ("JDPower Reliability",
             f"https://www.jdpower.com/cars/{year}/{make}/{model}"
             if all([year, make, model]) else "N/A — decode first"),
        ]
        for label, url in extra_pivots:
            if url != "N/A — decode first":
                results.add("History Pivots", label, url, "Generated")
