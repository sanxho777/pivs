# ============================================================
# utils.py
# ============================================================
import requests
from typing import Optional, Dict, Any


HEADERS = {
    "User-Agent": "PivotHarvest/1.0 (OSINT research tool)",
    "Accept":     "application/json",
}

TIMEOUT = 10  # seconds


def safe_get(url: str,
             params: Optional[Dict] = None,
             headers: Optional[Dict] = None,
             timeout: int = TIMEOUT) -> Optional[requests.Response]:
    """GET with sane defaults; returns None on any network failure."""
    try:
        merged_headers = {**HEADERS, **(headers or {})}
        resp = requests.get(url, params=params,
                            headers=merged_headers, timeout=timeout)
        return resp
    except requests.RequestException:
        return None


def safe_json(resp: Optional[requests.Response]) -> Optional[Any]:
    if resp is None:
        return None
    try:
        return resp.json()
    except ValueError:
        return None
