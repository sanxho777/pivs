import phonenumbers
from phonenumbers import geocoder, carrier, timezone as pn_timezone

from .base import BaseModule, ResultSet
from utils import safe_get


class PhoneModule(BaseModule):

    @property
    def name(self) -> str:
        return "Phone Intelligence"

    def run(self, pivot: str, results: ResultSet) -> None:
        self._parse_number(pivot, results)
        self._generate_pivots(pivot, results)

    def enrich(self, pivot: str, results: ResultSet) -> None:
        self._enrich_whatsapp_check(pivot, results)
        self._enrich_social_lookups(pivot, results)
        self._enrich_spam_check(pivot, results)
        self._enrich_deep_pivots(pivot, results)

    # ── run() methods ─────────────────────────────────────────

    def _parse_number(self, raw: str, results: ResultSet) -> None:
        parsed = None
        for region in [None, "US"]:
            try:
                parsed = phonenumbers.parse(raw, region)
                break
            except phonenumbers.NumberParseException:
                continue

        if not parsed:
            results.add_error(f"phonenumbers: could not parse '{raw}'")
            return

        src = "Google libphonenumber"

        is_valid    = phonenumbers.is_valid_number(parsed)
        is_possible = phonenumbers.is_possible_number(parsed)
        results.add("Validity", "Valid Number",
                    "Yes" if is_valid    else "No", src)
        results.add("Validity", "Possible Number",
                    "Yes" if is_possible else "No", src)

        results.add("Formatting", "E.164",
                    phonenumbers.format_number(
                        parsed, phonenumbers.PhoneNumberFormat.E164), src)
        results.add("Formatting", "International",
                    phonenumbers.format_number(
                        parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL), src)
        results.add("Formatting", "National",
                    phonenumbers.format_number(
                        parsed, phonenumbers.PhoneNumberFormat.NATIONAL), src)
        results.add("Formatting", "RFC 3966",
                    phonenumbers.format_number(
                        parsed, phonenumbers.PhoneNumberFormat.RFC3966), src)

        region_code = phonenumbers.region_code_for_number(parsed)
        if region_code:
            results.add("Location", "Country Code", region_code, src)

        geo = geocoder.description_for_number(parsed, "en")
        if geo:
            results.add("Location", "Geographic Description", geo, src)

        carr = carrier.name_for_number(parsed, "en")
        if carr:
            results.add("Carrier", "Carrier Name", carr, src)

        num_type = phonenumbers.number_type(parsed)
        type_map = {
            phonenumbers.PhoneNumberType.MOBILE:               "Mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE:           "Fixed Line",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed or Mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE:            "Toll-Free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE:         "Premium Rate",
            phonenumbers.PhoneNumberType.VOIP:                 "VoIP",
            phonenumbers.PhoneNumberType.PAGER:                "Pager",
            phonenumbers.PhoneNumberType.SHARED_COST:          "Shared Cost",
            phonenumbers.PhoneNumberType.UNKNOWN:              "Unknown",
        }
        results.add("Carrier", "Line Type",
                    type_map.get(num_type, "Unknown"), src)

        tzones = pn_timezone.time_zones_for_number(parsed)
        if tzones:
            results.add("Location", "Timezone(s)", ", ".join(tzones), src)

        results.add("Formatting", "Country Calling Code",
                    f"+{parsed.country_code}", src)
        results.add("Formatting", "National Number",
                    str(parsed.national_number), src)

    def _generate_pivots(self, raw: str, results: ResultSet) -> None:
        digits = "".join(c for c in raw if c.isdigit())

        e164        = raw
        digits_e164 = digits
        try:
            parsed      = phonenumbers.parse(raw, "US")
            e164        = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164
            )
            digits_e164 = e164.lstrip("+")
        except Exception:
            pass

        pivots = [
            ("WhatsApp",    f"https://wa.me/{digits_e164}"),
            ("Truecaller",  f"https://www.truecaller.com/search/us/{digits}"),
            ("Google Dork", f'https://www.google.com/search?q="{raw}" OR "{e164}"'),
            ("Telegram",    f"https://t.me/+{digits_e164}"),
            ("Sync.me",     f"https://sync.me/search/?number={digits_e164}"),
        ]
        for label, url in pivots:
            results.add("Search Pivots", label, url, "Generated")

    # ── enrich() methods ──────────────────────────────────────

    def _get_e164_digits(self, raw: str) -> str:
        try:
            parsed = phonenumbers.parse(raw, "US")
            e164   = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164
            )
            return e164.lstrip("+")
        except Exception:
            return "".join(c for c in raw if c.isdigit())

    def _enrich_whatsapp_check(self, raw: str,
                                results: ResultSet) -> None:
        digits = self._get_e164_digits(raw)
        resp   = safe_get(f"https://wa.me/{digits}", timeout=12)

        if resp and resp.status_code == 200:
            body = resp.text.lower()
            if "whatsapp" in body and ("send" in body or "chat" in body):
                results.add(
                    "WhatsApp Enrichment",
                    "Account Signal",
                    "WhatsApp page accessible — number may be active",
                    "wa.me",
                )
            else:
                results.add(
                    "WhatsApp Enrichment",
                    "Account Signal",
                    "Page returned but no clear WhatsApp profile signal",
                    "wa.me",
                )
        else:
            results.add(
                "WhatsApp Enrichment",
                "Account Signal",
                "No response or redirect",
                "wa.me",
            )

        results.add("WhatsApp Enrichment", "Direct Link",
                    f"https://wa.me/{digits}", "Generated")

    def _enrich_social_lookups(self, raw: str,
                                results: ResultSet) -> None:
        digits = self._get_e164_digits(raw)
        digits_plain = "".join(c for c in raw if c.isdigit())

        lookups = [
            ("NumLookup",          f"https://www.numlookup.com/?q={digits}"),
            ("CallerID Test",      f"https://www.calleridtest.com/lookup?number={digits}"),
            ("PhoneInfoga",        f"https://demo.phoneinfoga.crvx.fr/#/{digits}"),
            ("OpenCNAM",           f"https://www.opencnam.com/lookup/{digits}"),
            ("SpyDialer",          f"https://www.spydialer.com/default.aspx?phone={digits_plain}"),
            ("FreePhoneTracer",    f"https://www.freephonetracer.com/lookup.html?number={digits_plain}"),
            ("800notes",           f"https://800notes.com/Phone.aspx/{raw}"),
            ("WhoCalledMe",        f"https://whocallsme.com/Phone-Number.aspx/{digits_plain}"),
        ]
        for label, url in lookups:
            results.add("Phone Lookup Services", label, url, "Generated")

    def _enrich_spam_check(self, raw: str, results: ResultSet) -> None:
        digits = self._get_e164_digits(raw)

        spam_checks = [
            ("Tellows",     f"https://www.tellows.com/num/{digits}"),
            ("ShouldIAnswer",f"https://www.shouldianswer.net/phone-number/{digits}"),
            ("HiaMobile",   f"https://www.hiamobile.com/mobile/{digits}"),
            ("SpamCalls",   f"https://spamcalls.net/en/search?s={digits}"),
        ]
        for label, url in spam_checks:
            results.add("Spam / Reputation Checks", label, url, "Generated")

    def _enrich_deep_pivots(self, raw: str, results: ResultSet) -> None:
        digits = self._get_e164_digits(raw)

        deep = [
            ("Epieos",    f"https://epieos.com/?q=%2B{digits}&t=phone"),
            ("IntelX",    f"https://intelx.io/?s=%2B{digits}"),
            ("Google Dork Paste",
             f'https://www.google.com/search?q="{raw}" site:pastebin.com OR site:ghostbin.com'),
        ]
        for label, url in deep:
            results.add("Deep Search Pivots", label, url, "Generated")
