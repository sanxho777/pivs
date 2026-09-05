# ============================================================
# modules/exif_module.py
# ============================================================
import io
import os
import re
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import requests
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

from .base import BaseModule, ResultSet
from utils import safe_get

_SCRAPE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    )
}


def _dms_to_decimal(dms, ref: str) -> float:
    """Convert degrees/minutes/seconds tuple to decimal degrees."""
    try:
        degrees = float(dms[0])
        minutes = float(dms[1])
        seconds = float(dms[2])
        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 7)
    except Exception:
        return 0.0


class ExifModule(BaseModule):

    @property
    def name(self) -> str:
        return "Image / EXIF Intelligence"

    def run(self, pivot: str, results: ResultSet) -> None:
        """
        pivot is an image URL (http/https) or a local file path.
        """
        if pivot.startswith("http://") or pivot.startswith("https://"):
            self._from_url(pivot, results)
        elif os.path.isfile(pivot):
            self._from_file(pivot, results)
        else:
            results.add_error(f"EXIF: '{pivot}' is not a valid URL or file path")

    # ── Download and process ──────────────────────────────────
    def _from_url(self, url: str, results: ResultSet) -> None:
        results.add("Source", "Image URL", url, "Input")

        resp = safe_get(url, headers=_SCRAPE_HEADERS, timeout=20)
        if not resp or resp.status_code != 200:
            results.add_error(f"EXIF: could not fetch image (HTTP {resp.status_code if resp else 'timeout'})")
            return

        content_type = resp.headers.get("Content-Type", "")
        results.add("Source", "Content-Type", content_type, "HTTP Header")

        # File size
        size_bytes = len(resp.content)
        results.add("Source", "File Size",
                    f"{size_bytes:,} bytes ({size_bytes/1024:.1f} KB)",
                    "HTTP Header")

        # Last modified
        last_mod = resp.headers.get("Last-Modified", "")
        if last_mod:
            results.add("Source", "Last-Modified", last_mod, "HTTP Header")

        # CDN / hosting signals from headers
        for header, label in [
            ("cf-ray",       "Cloudflare CDN"),
            ("x-amz-cf-id",  "AWS CloudFront"),
            ("x-vercel-id",  "Vercel"),
            ("x-azure-ref",  "Azure CDN"),
        ]:
            if header in {k.lower() for k in resp.headers}:
                results.add("Hosting", label, "Detected", "HTTP Headers")

        try:
            img_data = io.BytesIO(resp.content)
            self._process_image(img_data, results)
        except Exception as ex:
            results.add_error(f"EXIF processing: {ex}")

        # Reverse image pivots regardless of EXIF availability
        self._reverse_image_pivots(url, results)

    def _from_file(self, path: str, results: ResultSet) -> None:
        results.add("Source", "File Path", path, "Input")
        size = os.path.getsize(path)
        results.add("Source", "File Size",
                    f"{size:,} bytes ({size/1024:.1f} KB)", "Local")
        try:
            with open(path, "rb") as f:
                self._process_image(f, results)
        except Exception as ex:
            results.add_error(f"EXIF processing: {ex}")

    # ── Core EXIF extraction ───────────────────────────────────
    def _process_image(self, data, results: ResultSet) -> None:
        try:
            img = Image.open(data)
        except Exception as ex:
            results.add_error(f"PIL could not open image: {ex}")
            return

        results.add("Image Info", "Format",
                    img.format or "Unknown", "Pillow")
        results.add("Image Info", "Mode",   img.mode,  "Pillow")
        results.add("Image Info", "Size",
                    f"{img.width} × {img.height} px", "Pillow")

        # Animated GIF frame count
        try:
            results.add("Image Info", "Frames",
                        str(img.n_frames), "Pillow")
        except AttributeError:
            pass

        # EXIF data
        exif_data = img._getexif() if hasattr(img, "_getexif") else None
        if not exif_data:
            results.add("EXIF", "Status", "No EXIF data found", "Pillow")
            return

        results.add("EXIF", "Status", "EXIF data present", "Pillow")

        gps_info: Dict[str, Any] = {}

        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, str(tag_id))

            if tag == "GPSInfo":
                for gps_tag_id, gps_val in value.items():
                    gps_tag = GPSTAGS.get(gps_tag_id, str(gps_tag_id))
                    gps_info[gps_tag] = gps_val
                continue

            # Skip binary / thumbnail blobs
            if isinstance(value, bytes) and len(value) > 64:
                continue

            # Human-readable value formatting
            display = str(value)
            if len(display) > 200:
                display = display[:200] + "..."

            # Flag high-signal EXIF fields
            high_signal = {
                "Make", "Model", "Software", "DateTime",
                "DateTimeOriginal", "DateTimeDigitized",
                "Artist", "Copyright", "ImageDescription",
                "XPAuthor", "XPComment", "XPKeywords",
                "CameraOwnerName", "BodySerialNumber",
                "LensModel", "LensSerialNumber",
                "UserComment",
            }

            category = "EXIF — High Signal" if tag in high_signal else "EXIF — Technical"
            results.add(category, tag, display, "Pillow/EXIF")

        # GPS parsing
        if gps_info:
            self._parse_gps(gps_info, results)

    # ── GPS coordinate extraction ──────────────────────────────
    def _parse_gps(self, gps_info: Dict, results: ResultSet) -> None:
        try:
            lat_dms  = gps_info.get("GPSLatitude")
            lat_ref  = gps_info.get("GPSLatitudeRef",  "N")
            lon_dms  = gps_info.get("GPSLongitude")
            lon_ref  = gps_info.get("GPSLongitudeRef", "E")
            altitude = gps_info.get("GPSAltitude")
            speed    = gps_info.get("GPSSpeed")
            ts       = gps_info.get("GPSTimeStamp")
            date     = gps_info.get("GPSDateStamp")

            if lat_dms and lon_dms:
                lat = _dms_to_decimal(lat_dms, lat_ref)
                lon = _dms_to_decimal(lon_dms, lon_ref)

                results.add("GPS — HIGH VALUE", "Latitude",
                            str(lat), "EXIF/GPS")
                results.add("GPS — HIGH VALUE", "Longitude",
                            str(lon), "EXIF/GPS")
                results.add("GPS — HIGH VALUE", "Decimal Coords",
                            f"{lat}, {lon}", "EXIF/GPS")
                results.add("GPS — HIGH VALUE", "Google Maps",
                            f"https://maps.google.com/?q={lat},{lon}",
                            "Generated")
                results.add("GPS — HIGH VALUE", "OpenStreetMap",
                            f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}",
                            "Generated")

            if altitude:
                results.add("GPS — HIGH VALUE", "Altitude",
                            f"{float(altitude):.1f} m", "EXIF/GPS")

            if speed:
                results.add("GPS", "Speed",
                            f"{float(speed):.1f} km/h", "EXIF/GPS")

            if date and ts:
                h = int(float(ts[0]))
                m = int(float(ts[1]))
                s = int(float(ts[2]))
                results.add("GPS — HIGH VALUE", "Capture Timestamp (UTC)",
                            f"{date} {h:02d}:{m:02d}:{s:02d}",
                            "EXIF/GPS")

        except Exception as ex:
            results.add_error(f"GPS parsing: {ex}")

    # ── Reverse image pivots ───────────────────────────────────
    def _reverse_image_pivots(self, url: str,
                               results: ResultSet) -> None:
        from urllib.parse import quote
        enc = quote(url, safe="")
        pivots = [
            ("Google Lens",
             f"https://lens.google.com/uploadbyurl?url={enc}"),
            ("TinEye",
             f"https://tineye.com/search?url={enc}"),
            ("Yandex Images",
             f"https://yandex.com/images/search?url={enc}&rpt=imageview"),
            ("Bing Visual Search",
             f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{enc}"),
        ]
        for label, link in pivots:
            results.add("Reverse Image Search", label, link, "Generated")
