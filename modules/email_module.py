import hashlib
import re
import time
import dns.resolver
import whois

from .base import BaseModule, ResultSet
from utils import safe_get, safe_json

_DISPOSABLE_URL = (
    "https://raw.githubusercontent.com/disposable-email-domains/"
    "disposable-email-domains/master/disposable_email_blocklist.conf"
)
_WHATSMYNAME_URL = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
)
_WMN_BLOCKLIST = {
    "ebay", "amazon", "apple", "google", "microsoft",
    "pornhub", "xvideos", "xhamster",
}
_disposable_cache: set = set()


def _load_disposable_domains() -> set:
    global _disposable_cache
    if _disposable_cache:
        return _disposable_cache
    resp = safe_get(_DISPOSABLE_URL)
    if resp and resp.status_code == 200:
        _disposable_cache = {
            line.strip().lower()
            for line in resp.text.splitlines()
            if line.strip() and not line.startswith("#")
        }
    return _disposable_cache


class EmailModule(BaseModule):

    @property
    def name(self) -> str:
        return "Email Intelligence"

    def run(self, pivot: str, results: ResultSet) -> None:
        from .paste_module import PasteModule
        self._parse_components(pivot, results)
        self._mx_records(pivot, results)
        self._gravatar_check(pivot, results)
        self._emailrep_check(pivot, results)
        self._disposable_check(pivot, results)
        self._domain_whois(pivot, results)
        self._generate_pivots(pivot, results)
        PasteModule().sweep(pivot, results, label="Paste / Leak Sites")

    def enrich(self, pivot: str, results: ResultSet) -> None:
        self._enrich_gravatar_profile(pivot, results)
        self._enrich_github_search(pivot, results)
        self._enrich_username_wmn(pivot, results)
        self._enrich_additional_pivots(pivot, results)

    # ── run() methods ─────────────────────────────────────────

    def _parse_components(self, email: str, results: ResultSet) -> None:
        at = email.find("@")
        if at == -1:
            results.add_error("Email: missing @ symbol")
            return

        username = email[:at]
        domain   = email[at + 1:]

        results.add("Identity", "Username",       username, "Local Parse")
        results.add("Identity", "Domain",         domain,   "Local Parse")

        known = {
            "gmail.com":      "Google",
            "yahoo.com":      "Yahoo",
            "outlook.com":    "Microsoft",
            "hotmail.com":    "Microsoft",
            "live.com":       "Microsoft",
            "protonmail.com": "Proton (E2E Encrypted)",
            "pm.me":          "Proton (E2E Encrypted)",
            "icloud.com":     "Apple",
            "me.com":         "Apple",
            "aol.com":        "AOL",
            "zoho.com":       "Zoho",
            "tutanota.com":   "Tutanota (E2E Encrypted)",
            "fastmail.com":   "FastMail",
        }
        provider = known.get(domain.lower(), "Custom / Corporate")
        results.add("Provider", "Email Provider", provider, "Local Parse")

        name_pat = re.search(r"([a-zA-Z]{2,})[.\-_]([a-zA-Z]{2,})", username)
        if name_pat:
            results.add("Identity", "Likely First Name",
                        name_pat.group(1).capitalize(), "Username Pattern")
            results.add("Identity", "Likely Last Name",
                        name_pat.group(2).capitalize(), "Username Pattern")

    def _mx_records(self, email: str, results: ResultSet) -> None:
        domain = email.split("@")[-1]
        try:
            answers = dns.resolver.resolve(domain, "MX")
            for rdata in sorted(answers, key=lambda r: r.preference):
                results.add("DNS / Mail", "MX Record",
                            f"{rdata.exchange} (priority {rdata.preference})",
                            "dnspython")
        except Exception as ex:
            results.add_error(f"MX lookup: {ex}")

        try:
            txt_answers = dns.resolver.resolve(domain, "TXT")
            for rdata in txt_answers:
                txt = rdata.to_text().strip('"')
                if "spf" in txt.lower() or "v=spf" in txt.lower():
                    results.add("DNS / Mail", "SPF Record", txt, "dnspython")
                elif "dmarc" in txt.lower():
                    results.add("DNS / Mail", "DMARC", txt, "dnspython")
        except Exception:
            pass

    def _gravatar_check(self, email: str, results: ResultSet) -> None:
        md5_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
        url  = f"https://www.gravatar.com/avatar/{md5_hash}?d=404"
        resp = safe_get(url)

        if resp and resp.status_code == 200:
            results.add("Profile", "Gravatar",
                        f"EXISTS — https://www.gravatar.com/{md5_hash}",
                        "gravatar.com")
            results.add("Profile", "Gravatar Avatar URL",
                        f"https://www.gravatar.com/avatar/{md5_hash}",
                        "gravatar.com")
        else:
            results.add("Profile", "Gravatar", "No profile found", "gravatar.com")

    def _emailrep_check(self, email: str, results: ResultSet) -> None:
        resp = safe_get(f"https://emailrep.io/{email}",
                        headers={"User-Agent": "PivotHarvest"})
        data = safe_json(resp)

        if not data:
            results.add_error("emailrep.io: no response")
            return

        src = "emailrep.io"
        results.add("Reputation", "Risk Level",
                    data.get("risk", "unknown"), src)
        results.add("Reputation", "Suspicious",
                    "Yes" if data.get("suspicious") else "No", src)

        details  = data.get("details", {})
        flag_map = {
            "Blacklisted":        "blacklisted",
            "Malicious Activity": "malicious_activity",
            "Credential Leak":    "credentials_leaked",
            "Data Breach":        "data_breach",
            "Domain Exists":      "domain_exists",
            "Domain Reputation":  "domain_reputation",
            "Free Provider":      "free_provider",
            "Disposable":         "disposable",
            "Deliverable":        "deliverable",
            "Spoofable":          "spoofable",
            "SPF Strict":         "spf_strict",
            "DMARC Enforced":     "dmarc_enforced",
            "First Seen":         "first_seen",
            "Last Seen":          "last_seen",
            "Profiles Found":     "profiles",
        }
        for label, key in flag_map.items():
            val = details.get(key)
            if val is None:
                continue
            if isinstance(val, bool):
                results.add("Reputation", label, "Yes" if val else "No", src)
            elif isinstance(val, list):
                results.add("Reputation", label, ", ".join(val) or "(none)", src)
            else:
                results.add("Reputation", label, str(val), src)

    def _disposable_check(self, email: str, results: ResultSet) -> None:
        domain         = email.split("@")[-1].lower()
        disposable_list = _load_disposable_domains()

        if domain in disposable_list:
            results.add("Reputation", "Disposable Domain",
                        "YES — known throwaway provider",
                        "disposable-email-domains (GitHub)")
        else:
            results.add("Reputation", "Disposable Domain",
                        "Not in blocklist",
                        "disposable-email-domains (GitHub)")

    def _domain_whois(self, email: str, results: ResultSet) -> None:
        domain = email.split("@")[-1]
        try:
            w = whois.whois(domain)
            if w:
                for label, attr in [
                    ("Registrar",       "registrar"),
                    ("Creation Date",   "creation_date"),
                    ("Expiration Date", "expiration_date"),
                    ("Updated Date",    "updated_date"),
                    ("Name Servers",    "name_servers"),
                    ("Registrant Org",  "org"),
                    ("Registrant Email","emails"),
                    ("Domain Status",   "status"),
                ]:
                    val = getattr(w, attr, None)
                    if val:
                        if isinstance(val, list):
                            val = val[0] if len(val) == 1 else ", ".join(
                                str(v) for v in val[:5]
                            )
                        results.add("Domain WHOIS", label,
                                    str(val), "python-whois")
        except Exception as ex:
            results.add_error(f"Domain WHOIS: {ex}")

    def _generate_pivots(self, email: str, results: ResultSet) -> None:
        encoded = email.replace("@", "%40")
        pivots  = [
            ("Google",    f'https://www.google.com/search?q="{email}"'),
            ("LinkedIn",  f"https://www.linkedin.com/search/results/people/?keywords={encoded}"),
            ("Twitter/X", f'https://twitter.com/search?q="{email}"'),
            ("GitHub",    f"https://github.com/search?q={encoded}&type=users"),
            ("Pastebin",  f'https://www.google.com/search?q=site:pastebin.com+"{email}"'),
        ]
        for label, url in pivots:
            results.add("Search Pivots", label, url, "Generated")

    # ── enrich() methods ──────────────────────────────────────

    def _enrich_gravatar_profile(self, email: str, results: ResultSet) -> None:
        md5_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
        resp     = safe_get(f"https://www.gravatar.com/{md5_hash}.json",
                            timeout=10)

        if not resp or resp.status_code != 200:
            return

        try:
            data  = resp.json()
            entry = data.get("entry", [{}])[0]
            src   = "gravatar.com/profile.json"

            for label, key in [
                ("Preferred Username", "preferredUsername"),
                ("Display Name",       "displayName"),
                ("About Me",           "aboutMe"),
                ("Location",           "currentLocation"),
                ("Profile URL",        "profileUrl"),
            ]:
                val = entry.get(key)
                if val:
                    results.add("Gravatar Profile", label, str(val), src)

            name_obj = entry.get("name", {})
            if isinstance(name_obj, dict) and name_obj.get("formatted"):
                results.add("Gravatar Profile", "Full Name",
                            name_obj["formatted"], src)

            for acct in entry.get("accounts", [])[:10]:
                shortname = acct.get("shortname", "")
                url       = acct.get("url", "")
                if shortname and url:
                    results.add("Gravatar Profile",
                                f"Linked Account: {shortname}", url, src)

            for url_obj in entry.get("urls", [])[:8]:
                val = url_obj.get("value", "")
                if val:
                    results.add("Gravatar Profile", "Linked URL", val, src)

            avatar = entry.get("thumbnailUrl", "")
            if avatar:
                results.add("Gravatar Profile", "Avatar URL", avatar, src)

        except Exception as ex:
            results.add_error(f"Gravatar profile JSON: {ex}")

    def _enrich_github_search(self, email: str, results: ResultSet) -> None:
        # Try commit search first (requires preview header)
        resp = safe_get(
            "https://api.github.com/search/commits",
            params={"q": f"author-email:{email}", "per_page": 10},
            headers={"Accept": "application/vnd.github.cloak-preview+json"},
            timeout=15,
        )

        if resp and resp.status_code == 200:
            try:
                data  = resp.json()
                total = data.get("total_count", 0)
                results.add("GitHub Commits", "Total Found",
                            str(total), "api.github.com")

                seen_names = set()
                for item in data.get("items", [])[:10]:
                    commit      = item.get("commit", {})
                    author      = commit.get("author", {})
                    repo        = item.get("repository", {}).get("full_name", "")
                    url         = item.get("html_url", "")
                    author_name = author.get("name", "")

                    if author_name and author_name not in seen_names:
                        results.add("GitHub Commits", "Author Name",
                                    author_name, "api.github.com")
                        seen_names.add(author_name)

                    if repo and url:
                        results.add("GitHub Commits",
                                    f"Commit in {repo}", url,
                                    "api.github.com")
                return
            except Exception:
                pass

        # Fall back to code search
        time.sleep(6)
        resp2 = safe_get(
            "https://api.github.com/search/code",
            params={"q": email, "per_page": 10},
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=15,
        )

        if not resp2 or resp2.status_code not in (200, 422):
            results.add_error(
                f"GitHub search: HTTP {resp2.status_code if resp2 else 'no response'}"
            )
            return

        if resp2.status_code == 403:
            results.add("GitHub", "Code Search",
                        "Rate limited — retry in 60s", "api.github.com")
            return

        try:
            data  = resp2.json()
            total = data.get("total_count", 0)
            results.add("GitHub Code Search", "Total Mentions",
                        str(total), "api.github.com")
            for item in data.get("items", [])[:10]:
                repo = item.get("repository", {}).get("full_name", "")
                url  = item.get("html_url", "")
                if repo and url:
                    results.add("GitHub Code Search",
                                f"Found in {repo}", url,
                                "api.github.com")
        except Exception as ex:
            results.add_error(f"GitHub code search parse: {ex}")

    def _enrich_username_wmn(self, email: str, results: ResultSet) -> None:
        from username_checker import run_username_check

        username = email.split("@")[0]
        if not username or len(username) < 3:
            return

        resp = safe_get(_WHATSMYNAME_URL, timeout=20)
        if not resp or resp.status_code != 200:
            return

        try:
            data = resp.json()
        except ValueError:
            return

        # Top 75 sites only — keeps enrichment fast
        sites = [
            s for s in data.get("sites", [])[:75]
            if s.get("name", "").lower() not in _WMN_BLOCKLIST
            and s.get("uri_check")
            and "{account}" in s.get("uri_check", "")
            and s.get("e_string")
        ]

        hits = run_username_check(sites, [username], show_progress=False)

        if hits:
            results.add(
                "Username from Email (WMN)",
                "Hits Found",
                str(len(hits)),
                "WhatsMyName async check",
            )
            for hit in hits:
                results.add(
                    "Username from Email (WMN)",
                    hit.site_name,
                    hit.url,
                    "WhatsMyName async check",
                )
        else:
            results.add(
                "Username from Email (WMN)",
                "Result",
                f"No hits for '{username}' across {len(sites)} sites (top-75 scan)",
                "WhatsMyName async check",
            )

    def _enrich_additional_pivots(self, email: str,
                                   results: ResultSet) -> None:
        encoded = email.replace("@", "%40")
        pivots  = [
            ("HaveIBeenPwned Manual",
             f"https://haveibeenpwned.com/account/{encoded}"),
            ("DeHashed",
             f"https://dehashed.com/search?query={encoded}"),
            ("LeakCheck",
             f"https://leakcheck.io/?query={encoded}"),
            ("IntelX",
             f"https://intelx.io/?s={encoded}"),
            ("Epieos",
             f"https://epieos.com/?q={email}&t=email"),
            ("GHunt (Google)",
             f"https://www.google.com/search?q=site:accounts.google.com+{encoded}"),
        ]
        for label, url in pivots:
            results.add("Deep Search Pivots", label, url, "Generated")
