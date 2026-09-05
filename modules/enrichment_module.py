# ============================================================
# modules/enrichment_module.py
# — Profile scraping + reverse image pivot generation
# ============================================================
import re
from typing import Optional
from urllib.parse import quote, urlparse

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

_FOLLOWER_RE = re.compile(
    r"([\d,\.]+[KkMm]?)\s*(?:Followers|followers|FOLLOWERS)",
    re.IGNORECASE,
)
_FOLLOWING_RE = re.compile(
    r"([\d,\.]+[KkMm]?)\s*(?:Following|following)",
    re.IGNORECASE,
)
_JOINED_RE = re.compile(
    r"(?:Joined|Member since|joined)\s+([A-Za-z]+\s+\d{4}|\d{4})",
    re.IGNORECASE,
)


class EnrichmentModule:
    """
    Secondary module — enriches a confirmed profile URL with
    scraped metadata and reverse image search pivots.
    Not a standalone pivot type.
    """

    def enrich(self, profile_url: str, site_name: str,
               results: ResultSet) -> None:
        self._scrape_profile(profile_url, site_name, results)

    def _scrape_profile(self, url: str, site_name: str,
                        results: ResultSet) -> None:
        # Guarantee site_name is never blank in errors or findings
        label = site_name.strip() if site_name.strip() else "Unknown"

        resp = safe_get(url, headers=_SCRAPE_HEADERS, timeout=15)
        if not resp or resp.status_code != 200:
            code = resp.status_code if resp else "no response"
            results.add_error(f"Enrichment [{label}]: HTTP {code}")
            return

        try:
            soup = BeautifulSoup(resp.text, "lxml")
        except Exception:
            soup = BeautifulSoup(resp.text, "html.parser")

        cat = f"Profile Enrichment — {label}"

        # Page title
        title = soup.find("title")
        if title and title.get_text(strip=True):
            results.add(cat, "Page Title",
                        title.get_text(strip=True)[:120], label)

        # Meta description
        meta_desc = (
            soup.find("meta", attrs={"name": "description"})
            or soup.find("meta", attrs={"property": "og:description"})
        )
        if meta_desc and meta_desc.get("content"):
            results.add(cat, "Description",
                        meta_desc["content"][:200], label)

        # OG title
        og_title = soup.find("meta", attrs={"property": "og:title"})
        if og_title and og_title.get("content"):
            results.add(cat, "OG Title",
                        og_title["content"][:120], label)

        # Avatar / profile image
        avatar_url = self._find_avatar(soup, url)
        if avatar_url:
            results.add(cat, "Avatar URL", avatar_url, label)
            self._reverse_image_pivots(avatar_url, cat, results)

        # Follower / following counts from page text
        page_text = soup.get_text(" ", strip=True)

        followers = _FOLLOWER_RE.search(page_text)
        if followers:
            results.add(cat, "Followers", followers.group(1), label)

        following = _FOLLOWING_RE.search(page_text)
        if following:
            results.add(cat, "Following", following.group(1), label)

        joined = _JOINED_RE.search(page_text)
        if joined:
            results.add(cat, "Joined", joined.group(1), label)

        # External links in profile
        links = self._extract_external_links(soup, url)
        for link in links[:10]:
            results.add(cat, "Linked URL", link, label)

        # Twitter card data
        for prop in ["twitter:site", "twitter:creator", "twitter:title"]:
            tag = soup.find("meta", attrs={"name": prop})
            if tag and tag.get("content"):
                results.add(cat, prop, tag["content"], label)

    def _find_avatar(self, soup: BeautifulSoup,
                     page_url: str) -> Optional[str]:
        """
        Try multiple common avatar patterns across major platforms.
        """
        # og:image is the most reliable cross-platform signal
        og_img = soup.find("meta", attrs={"property": "og:image"})
        if og_img and og_img.get("content"):
            return og_img["content"]

        # Twitter card image
        tw_img = soup.find("meta", attrs={"name": "twitter:image"})
        if tw_img and tw_img.get("content"):
            return tw_img["content"]

        # img tags with avatar/profile in class, id, or src
        for img in soup.find_all("img"):
            src = img.get("src", "")
            cls = " ".join(img.get("class", []))
            alt = img.get("alt", "")
            if any(x in (src + cls + alt).lower()
                   for x in ["avatar", "profile-pic", "profile_pic",
                              "user-photo", "userpic"]):
                if src.startswith("http"):
                    return src
                elif src.startswith("//"):
                    return "https:" + src

        return None

    def _reverse_image_pivots(self, image_url: str,
                               cat: str, results: ResultSet) -> None:
        enc = quote(image_url, safe="")
        pivots = [
            ("Reverse Image — Google Lens",
             f"https://lens.google.com/uploadbyurl?url={enc}"),
            ("Reverse Image — TinEye",
             f"https://tineye.com/search?url={enc}"),
            ("Reverse Image — Yandex",
             f"https://yandex.com/images/search?url={enc}&rpt=imageview"),
            ("Reverse Image — Bing Visual",
             f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{enc}"),
        ]
        for lbl, url in pivots:
            results.add(cat, lbl, url, "Generated")

    def _extract_external_links(self, soup: BeautifulSoup,
                                 page_url: str) -> list:
        base_domain = urlparse(page_url).netloc
        external = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("http"):
                link_domain = urlparse(href).netloc
                if link_domain and link_domain != base_domain:
                    if href not in external:
                        external.append(href)
        return external
