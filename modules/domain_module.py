import re
import socket
from typing import Set
from urllib.parse import urlparse

import dns.resolver
import whois
from bs4 import BeautifulSoup

from .base import BaseModule, ResultSet
from utils import safe_get, safe_json

_SCRAPE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}


class DomainModule(BaseModule):

    @property
    def name(self) -> str:
        return "Domain Intelligence"

    def run(self, pivot: str, results: ResultSet) -> None:
        domain = pivot.lower().strip().lstrip("www.").rstrip("/")
        results.add("Domain", "Normalized", domain, "Local Parse")
        self._dns_full(domain, results)
        self._whois_domain(domain, results)
        self._wayback(domain, results)
        self._crt_sh(domain, results)
        self._hackertarget_subdomains(domain, results)
        self._http_headers(domain, results)
        self._generate_pivots(domain, results)

    def enrich(self, pivot: str, results: ResultSet) -> None:
        domain = pivot.lower().strip().lstrip("www.").rstrip("/")
        self._enrich_robots(domain, results)
        self._enrich_sitemap(domain, results)
        self._enrich_security_txt(domain, results)
        self._enrich_ssl(domain, results)
        self._enrich_homepage(domain, results)
        self._enrich_dns_history(domain, results)

    # ── run() methods ─────────────────────────────────────────

    def _dns_full(self, domain: str, results: ResultSet) -> None:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for rdata in answers:
                    results.add(f"DNS — {rtype}", rtype,
                                rdata.to_text().strip('"'), "dnspython")
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                results.add_error(f"DNS: {domain} does not exist (NXDOMAIN)")
                return
            except Exception as ex:
                results.add_error(f"DNS {rtype}: {ex}")

    def _whois_domain(self, domain: str, results: ResultSet) -> None:
        try:
            w = whois.whois(domain)
            if not w:
                return
            fields = [
                ("Registrar",        "registrar"),
                ("Creation Date",    "creation_date"),
                ("Expiration Date",  "expiration_date"),
                ("Updated Date",     "updated_date"),
                ("Name Servers",     "name_servers"),
                ("Registrant Org",   "org"),
                ("Registrant Email", "emails"),
                ("Status",           "status"),
                ("DNSSEC",           "dnssec"),
            ]
            for label, attr in fields:
                val = getattr(w, attr, None)
                if val:
                    if isinstance(val, list):
                        val = val[0] if len(val) == 1 \
                              else ", ".join(str(v) for v in val[:5])
                    results.add("WHOIS", label, str(val), "python-whois")
        except Exception as ex:
            results.add_error(f"Domain WHOIS: {ex}")

    def _wayback(self, domain: str, results: ResultSet) -> None:
        resp = safe_get(
            "https://archive.org/wayback/available",
            params={"url": domain},
        )
        data = safe_json(resp)
        if not data:
            return
        snap = data.get("archived_snapshots", {}).get("closest", {})
        if snap.get("available"):
            results.add("Wayback Machine", "Closest Snapshot",
                        snap.get("url", ""), "archive.org")
            results.add("Wayback Machine", "Snapshot Timestamp",
                        snap.get("timestamp", ""), "archive.org")
            results.add("Wayback Machine", "Full History",
                        f"https://web.archive.org/web/*/{domain}",
                        "archive.org")
        else:
            results.add("Wayback Machine", "Status",
                        "No snapshots found", "archive.org")

    def _crt_sh(self, domain: str, results: ResultSet) -> None:
        resp = safe_get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=20,
        )
        if not resp or resp.status_code != 200:
            results.add_error("crt.sh: no response")
            return

        try:
            data = resp.json()
        except ValueError:
            results.add_error("crt.sh: JSON parse error")
            return

        subdomains: Set[str] = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.splitlines():
                name = name.strip().lower().lstrip("*.")
                if name and name.endswith(domain) and name != domain:
                    subdomains.add(name)

        results.add("Certificate Transparency", "Total Certs Found",
                    str(len(data)), "crt.sh")
        results.add("Certificate Transparency", "Unique Subdomains",
                    str(len(subdomains)), "crt.sh")

        for sub in sorted(subdomains)[:50]:
            results.add("Subdomains", sub,
                        f"https://{sub}", "crt.sh")

        if len(subdomains) > 50:
            results.add("Subdomains",
                        f"... and {len(subdomains)-50} more",
                        "Query crt.sh directly for full list", "crt.sh")

    def _hackertarget_subdomains(self, domain: str,
                                  results: ResultSet) -> None:
        resp = safe_get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain},
        )
        if not resp or resp.status_code != 200:
            return

        text = resp.text.strip()
        if "error" in text.lower() or "no records" in text.lower():
            return

        seen = {
            f.value.split("//")[-1].rstrip("/")
            for f in results.findings
            if f.category == "Subdomains"
        }

        for line in text.splitlines():
            parts = line.split(",")
            if len(parts) >= 2:
                host = parts[0].strip()
                ip   = parts[1].strip()
                if host not in seen:
                    results.add("Subdomains", host,
                                f"IP: {ip}", "hackertarget.com")
                    seen.add(host)

    def _http_headers(self, domain: str, results: ResultSet) -> None:
        resp = safe_get(
            "https://api.hackertarget.com/httpheaders/",
            params={"q": f"https://{domain}"},
        )
        if not resp or resp.status_code != 200:
            return

        text = resp.text.strip()
        if "error" in text.lower():
            return

        interesting = [
            "server", "x-powered-by", "x-generator",
            "x-drupal-cache", "cf-ray", "x-vercel",
            "x-amz", "x-azure",
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
        ]
        for line in text.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                key = key.strip().lower()
                val = val.strip()
                if any(key.startswith(k) for k in interesting):
                    results.add("HTTP Headers / Tech Stack",
                                key, val, "hackertarget.com")

    def _generate_pivots(self, domain: str, results: ResultSet) -> None:
        pivots = [
            ("Shodan",         f"https://www.shodan.io/domain/{domain}"),
            ("VirusTotal",     f"https://www.virustotal.com/gui/domain/{domain}"),
            ("URLScan.io",     f"https://urlscan.io/search/#{domain}"),
            ("SecurityTrails", f"https://securitytrails.com/domain/{domain}/dns"),
            ("DNSdumpster",    f"https://dnsdumpster.com/ (search: {domain})"),
            ("Google Dork",    f"https://www.google.com/search?q=site:{domain}"),
        ]
        for label, url in pivots:
            results.add("Recon Pivots", label, url, "Generated")

    # ── enrich() methods ──────────────────────────────────────

    def _enrich_robots(self, domain: str, results: ResultSet) -> None:
        for scheme in ["https", "http"]:
            resp = safe_get(
                f"{scheme}://{domain}/robots.txt",
                headers=_SCRAPE_HEADERS,
                timeout=10,
            )
            if resp and resp.status_code == 200 \
                    and "user-agent" in resp.text.lower():
                lines      = resp.text.splitlines()
                disallowed = [l for l in lines
                              if l.lower().startswith("disallow:")]
                sitemaps   = [l for l in lines
                              if l.lower().startswith("sitemap:")]

                results.add("robots.txt", "Total Lines",
                            str(len(lines)),
                            f"{scheme}://{domain}/robots.txt")
                results.add("robots.txt", "Disallowed Count",
                            str(len(disallowed)),
                            f"{scheme}://{domain}/robots.txt")

                for d in disallowed[:20]:
                    path = d.split(":", 1)[-1].strip()
                    if path:
                        results.add("robots.txt", "Disallowed Path",
                                    path,
                                    f"{scheme}://{domain}/robots.txt")

                for s in sitemaps:
                    sm = s.split(":", 1)[-1].strip()
                    if sm:
                        results.add("robots.txt", "Sitemap Reference",
                                    sm,
                                    f"{scheme}://{domain}/robots.txt")
                break

    def _enrich_sitemap(self, domain: str, results: ResultSet) -> None:
        for path in ["/sitemap.xml", "/sitemap_index.xml",
                     "/sitemap.xml.gz", "/wp-sitemap.xml"]:
            resp = safe_get(
                f"https://{domain}{path}",
                headers=_SCRAPE_HEADERS,
                timeout=12,
            )
            if resp and resp.status_code == 200 and len(resp.text) > 50:
                url_count = resp.text.count("<loc>")
                src       = f"https://{domain}{path}"

                results.add("Sitemap", "Sitemap URL", src, "Discovered")
                results.add("Sitemap", "URL Count",
                            str(url_count), src)

                locs = re.findall(r"<loc>(.*?)</loc>", resp.text)[:8]
                for loc in locs:
                    results.add("Sitemap", "Sample URL", loc, src)
                break

    def _enrich_security_txt(self, domain: str,
                              results: ResultSet) -> None:
        for path in ["/.well-known/security.txt", "/security.txt"]:
            resp = safe_get(
                f"https://{domain}{path}",
                headers=_SCRAPE_HEADERS,
                timeout=10,
            )
            if resp and resp.status_code == 200 \
                    and 10 < len(resp.text) < 5000:
                src = f"https://{domain}{path}"
                results.add("security.txt", "Found", src, "Discovered")

                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        key, _, val = line.partition(":")
                        results.add("security.txt",
                                    key.strip(), val.strip(), src)
                break

    def _enrich_ssl(self, domain: str, results: ResultSet) -> None:
        resp = safe_get(
            "https://api.hackertarget.com/sslcheck/",
            params={"q": f"https://{domain}"},
            timeout=20,
        )
        if not resp or resp.status_code != 200:
            return

        text = resp.text.strip()
        if "error" in text.lower():
            return

        src = "hackertarget.com/sslcheck"
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" in line:
                key, _, val = line.partition(":")
                key = key.strip()
                val = val.strip()
                if key and val:
                    results.add("SSL Certificate", key, val, src)

    def _enrich_homepage(self, domain: str, results: ResultSet) -> None:
        resp = safe_get(
            f"https://{domain}",
            headers=_SCRAPE_HEADERS,
            timeout=15,
        )
        if not resp or resp.status_code != 200:
            return

        try:
            soup = BeautifulSoup(resp.text, "lxml")
        except Exception:
            soup = BeautifulSoup(resp.text, "html.parser")

        src = f"https://{domain}"

        # Contact emails
        emails_found = list(set(
            re.findall(
                r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
                resp.text,
            )
        ))
        skip_domains = {"example.com", "schema.org", "w3.org",
                        "sentry.io", "google.com"}
        for email in emails_found[:8]:
            if not any(sd in email for sd in skip_domains):
                results.add("Homepage Intel", "Email Found", email, src)

        # Phone numbers
        phones = list(set(re.findall(
            r"[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}",
            resp.text,
        )))
        for phone in phones[:5]:
            results.add("Homepage Intel", "Phone Found", phone, src)

        # Social media links
        social_patterns = {
            "twitter.com/":          "Twitter/X",
            "x.com/":                "Twitter/X",
            "facebook.com/":         "Facebook",
            "instagram.com/":        "Instagram",
            "linkedin.com/company/": "LinkedIn",
            "linkedin.com/in/":      "LinkedIn",
            "youtube.com/":          "YouTube",
            "github.com/":           "GitHub",
            "tiktok.com/":           "TikTok",
            "t.me/":                 "Telegram",
            "discord.gg/":           "Discord",
            "discord.com/":          "Discord",
        }
        seen_socials: Set[str] = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            for pattern, label in social_patterns.items():
                if pattern in href and label not in seen_socials:
                    results.add("Homepage Social Links", label,
                                href, src)
                    seen_socials.add(label)

        # Meta generator tag (CMS fingerprint)
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen and gen.get("content"):
            results.add("Homepage Intel", "CMS / Generator",
                        gen["content"], src)

        # Description
        desc = soup.find("meta", attrs={"name": "description"})
        if desc and desc.get("content"):
            results.add("Homepage Intel", "Meta Description",
                        desc["content"][:200], src)

        # Copyright / org name
        cp = re.search(
            r"©\s*(\d{4})?[\s\-]*([A-Z][A-Za-z\s&,\.]{3,60})",
            resp.text,
        )
        if cp:
            results.add("Homepage Intel", "Copyright",
                        cp.group(0).strip()[:100], src)

    def _enrich_dns_history(self, domain: str,
                             results: ResultSet) -> None:
        resp = safe_get(
            "https://api.hackertarget.com/dnslookup/",
            params={"q": domain},
            timeout=15,
        )
        if not resp or resp.status_code != 200:
            return

        text = resp.text.strip()
        if "error" in text.lower():
            return

        for line in text.splitlines():
            if line.strip():
                results.add("DNS History", "Record",
                            line.strip(), "hackertarget.com")
