import socket
import whois
import dns.resolver

from .base import BaseModule, ResultSet
from utils import safe_get, safe_json


class IPModule(BaseModule):

    @property
    def name(self) -> str:
        return "IP Intelligence"

    def run(self, pivot: str, results: ResultSet) -> None:
        self._query_ip_api(pivot, results)
        self._query_ipinfo(pivot, results)
        self._reverse_dns(pivot, results)
        self._hackertarget_reverse_ip(pivot, results)
        self._hackertarget_dns(pivot, results)
        self._whois_asn(pivot, results)
        self._asn_cidr_expansion(pivot, results)

    def enrich(self, pivot: str, results: ResultSet) -> None:
        self._enrich_port_scan(pivot, results)
        self._enrich_tor_check(pivot, results)
        self._enrich_spamhaus(pivot, results)
        self._enrich_threat_pivots(pivot, results)

    # ── run() methods ─────────────────────────────────────────

    def _query_ip_api(self, ip: str, results: ResultSet) -> None:
        fields = (
            "status,message,country,countryCode,region,regionName,"
            "city,zip,lat,lon,timezone,isp,org,as,asname,"
            "reverse,mobile,proxy,hosting,query"
        )
        resp = safe_get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": fields},
        )
        data = safe_json(resp)

        if not data:
            results.add_error("ip-api.com: no response")
            return

        if data.get("status") != "success":
            results.add_error(f"ip-api.com: {data.get('message', 'failed')}")
            return

        src = "ip-api.com"
        geo_map = {
            "Country":      "country",
            "Country Code": "countryCode",
            "Region":       "regionName",
            "City":         "city",
            "ZIP":          "zip",
            "Latitude":     "lat",
            "Longitude":    "lon",
            "Timezone":     "timezone",
        }
        for label, key in geo_map.items():
            val = data.get(key)
            if val is not None and val != "":
                results.add("Geolocation", label, val, src)

        net_map = {
            "ISP":          "isp",
            "Organization": "org",
            "AS Number":    "as",
            "AS Name":      "asname",
            "Hostname":     "reverse",
        }
        for label, key in net_map.items():
            val = data.get(key)
            if val:
                results.add("Network", label, val, src)

        flag_map = {
            "Mobile Network": "mobile",
            "Proxy/VPN":      "proxy",
            "Hosting/DC":     "hosting",
        }
        for label, key in flag_map.items():
            val = data.get(key)
            if val is not None:
                results.add("Threat Flags", label,
                            "Yes" if val else "No", src)

    def _query_ipinfo(self, ip: str, results: ResultSet) -> None:
        resp = safe_get(f"https://ipinfo.io/{ip}/json")
        data = safe_json(resp)

        if not data or "bogon" in data:
            return

        src = "ipinfo.io"
        for label, key in [
            ("Org (ipinfo)",      "org"),
            ("Hostname (ipinfo)", "hostname"),
            ("Region (ipinfo)",   "region"),
            ("Postal",            "postal"),
        ]:
            val = data.get(key)
            if val:
                results.add("Network", label, val, src)

        if data.get("loc"):
            results.add("Geolocation", "Coords (ipinfo)", data["loc"], src)

    def _reverse_dns(self, ip: str, results: ResultSet) -> None:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            results.add("DNS", "Reverse Hostname",
                        hostname, "socket.gethostbyaddr")
        except socket.herror:
            results.add("DNS", "Reverse Hostname",
                        "(no PTR record)", "socket.gethostbyaddr")
        except Exception as ex:
            results.add_error(f"Reverse DNS: {ex}")

    def _hackertarget_reverse_ip(self, ip: str, results: ResultSet) -> None:
        resp = safe_get(
            "https://api.hackertarget.com/reverseiplookup/",
            params={"q": ip},
        )
        if not resp or resp.status_code != 200:
            results.add_error("HackerTarget reverseIP: no response")
            return

        text = resp.text.strip()
        if "error" in text.lower() or "no records" in text.lower():
            results.add("Shared Hosting", "Co-hosted Domains",
                        "(none found)", "hackertarget.com")
            return

        domains = [d.strip() for d in text.splitlines() if d.strip()]
        for d in domains[:20]:
            results.add("Shared Hosting", "Co-hosted Domain",
                        d, "hackertarget.com")

        if len(domains) > 20:
            results.add("Shared Hosting", "Additional Co-hosts",
                        f"{len(domains) - 20} more (truncated)",
                        "hackertarget.com")

    def _hackertarget_dns(self, ip: str, results: ResultSet) -> None:
        resp = safe_get(
            "https://api.hackertarget.com/dnslookup/",
            params={"q": ip},
        )
        if not resp or resp.status_code != 200:
            return

        text = resp.text.strip()
        if "error" not in text.lower():
            for line in text.splitlines():
                if line.strip():
                    results.add("DNS", "Record",
                                line.strip(), "hackertarget.com")

    def _whois_asn(self, ip: str, results: ResultSet) -> None:
        try:
            w = whois.whois(ip)
            if w:
                for label, attr in [
                    ("WHOIS Org",     "org"),
                    ("WHOIS Country", "country"),
                    ("WHOIS Emails",  "emails"),
                    ("WHOIS CIDR",    "cidr"),
                ]:
                    val = getattr(w, attr, None)
                    if val:
                        results.add(
                            "WHOIS", label,
                            ", ".join(val) if isinstance(val, list)
                            else str(val),
                            "python-whois",
                        )
        except Exception as ex:
            results.add_error(f"WHOIS: {ex}")

    def _asn_cidr_expansion(self, ip: str, results: ResultSet) -> None:
        resp = safe_get(
            "https://api.hackertarget.com/aslookup/",
            params={"q": ip},
        )
        if not resp or resp.status_code != 200:
            results.add_error("ASN lookup: no response")
            return

        text = resp.text.strip()
        if "error" in text.lower():
            return

        parts = [p.strip().strip('"') for p in text.split(",")]
        if len(parts) >= 4:
            asn      = parts[1]
            asn_name = ", ".join(parts[3:])
            results.add("ASN / CIDR", "ASN Number",
                        asn, "hackertarget.com")
            results.add("ASN / CIDR", "ASN Name",
                        asn_name, "hackertarget.com")
            results.add("ASN / CIDR", "BGP Viewer",
                        f"https://bgp.he.net/{asn}", "Generated")
            results.add("ASN / CIDR", "Shodan ASN",
                        f"https://www.shodan.io/search?query=asn:{asn}",
                        "Generated")

            if asn:
                ranges_resp = safe_get(
                    "https://api.hackertarget.com/asoutput/",
                    params={"q": f"AS{asn}"},
                    timeout=20,
                )
                if ranges_resp and ranges_resp.status_code == 200:
                    range_text = ranges_resp.text.strip()
                    if "error" not in range_text.lower():
                        cidrs = [
                            line.strip()
                            for line in range_text.splitlines()
                            if line.strip()
                        ]
                        results.add("ASN / CIDR", "Total CIDR Ranges",
                                    str(len(cidrs)), "hackertarget.com")
                        for cidr in cidrs[:20]:
                            results.add("ASN / CIDR", "CIDR Block",
                                        cidr, "hackertarget.com")
                        if len(cidrs) > 20:
                            results.add(
                                "ASN / CIDR",
                                f"... {len(cidrs)-20} more ranges",
                                "Query hackertarget directly",
                                "hackertarget.com",
                            )

    # ── enrich() methods ──────────────────────────────────────

    def _enrich_port_scan(self, ip: str, results: ResultSet) -> None:
        resp = safe_get(
            "https://api.hackertarget.com/nmap/",
            params={"q": ip},
            timeout=30,
        )
        if not resp or resp.status_code != 200:
            results.add_error("Port scan: no response from hackertarget")
            return

        text = resp.text.strip()
        if "error" in text.lower():
            results.add("Port Scan", "Status",
                        "Scan unavailable or rate limited",
                        "hackertarget.com/nmap")
            return

        open_ports = []
        for line in text.splitlines():
            line = line.strip()
            if "/tcp" in line or "/udp" in line:
                results.add("Port Scan", "Open Port",
                            line, "hackertarget.com/nmap")
                open_ports.append(line)

        if not open_ports:
            results.add("Port Scan", "Result",
                        "No open ports detected",
                        "hackertarget.com/nmap")
        else:
            results.add("Port Scan", "Total Open Ports",
                        str(len(open_ports)),
                        "hackertarget.com/nmap")

    def _enrich_tor_check(self, ip: str, results: ResultSet) -> None:
        resp = safe_get(
            "https://check.torproject.org/torbulkexitlist",
            timeout=15,
        )
        if not resp or resp.status_code != 200:
            results.add_error("Tor check: could not fetch exit node list")
            return

        exit_nodes = set(resp.text.splitlines())
        is_tor = ip.strip() in exit_nodes

        results.add(
            "Threat Intelligence",
            "Tor Exit Node",
            "YES — confirmed Tor exit node" if is_tor else "No",
            "torproject.org",
        )

    def _enrich_spamhaus(self, ip: str, results: ResultSet) -> None:
        try:
            reversed_ip = ".".join(reversed(ip.strip().split(".")))
            lookup      = f"{reversed_ip}.zen.spamhaus.org"

            try:
                answers = dns.resolver.resolve(lookup, "A")
                codes   = [str(r) for r in answers]
                results.add(
                    "Threat Intelligence",
                    "Spamhaus ZEN",
                    f"LISTED — return codes: {', '.join(codes)}",
                    "spamhaus.org/DNS",
                )
            except dns.resolver.NXDOMAIN:
                results.add(
                    "Threat Intelligence",
                    "Spamhaus ZEN",
                    "Not listed",
                    "spamhaus.org/DNS",
                )

        except Exception as ex:
            results.add_error(f"Spamhaus DNS check: {ex}")

    def _enrich_threat_pivots(self, ip: str, results: ResultSet) -> None:
        pivots = [
            ("AbuseIPDB",       f"https://www.abuseipdb.com/check/{ip}"),
            ("GreyNoise",       f"https://viz.greynoise.io/ip/{ip}"),
            ("ThreatBook",      f"https://threatbook.io/ip/{ip}"),
            ("IPVoid",          f"https://www.ipvoid.com/ip-blacklist-check/?ip={ip}"),
            ("MXToolbox",       f"https://mxtoolbox.com/blacklists.aspx?ip={ip}"),
            ("VirusTotal",      f"https://www.virustotal.com/gui/ip-address/{ip}"),
            ("Censys",          f"https://search.censys.io/hosts/{ip}"),
            ("Shodan",          f"https://www.shodan.io/host/{ip}"),
        ]
        for label, url in pivots:
            results.add("Threat Intel Pivots", label, url, "Generated")
