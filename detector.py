import re
from enum import Enum, auto
from urllib.parse import urlparse

_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp", "tiff", "bmp"}

# VIN: exactly 17 chars, alphanumeric, excluding I O Q
_VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$", re.IGNORECASE)

# License plate: 2–8 alphanumeric chars, allowing spaces and hyphens
_PLATE_RE = re.compile(r"^[A-Z0-9]{2,4}[\s\-]?[A-Z0-9]{2,4}[\s\-]?[A-Z0-9]{0,4}$",
                       re.IGNORECASE)


class PivotType(Enum):
    IP_ADDRESS    = auto()
    EMAIL         = auto()
    PHONE         = auto()
    DOMAIN        = auto()
    IMAGE         = auto()
    NAME          = auto()
    USERNAME      = auto()
    VIN           = auto()
    LICENSE_PLATE = auto()
    UNKNOWN       = auto()


_IPV4_RE     = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_EMAIL_RE    = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")
_PHONE_RE    = re.compile(
    r"^[\+]?[(]?[\d]{1,4}[)]?[-\s.]?[(]?[\d]{1,4}[)]?[-\s.]?[\d]{4,10}$"
)
_DOMAIN_RE   = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}$"
)
_NAME_RE     = re.compile(r"^[A-Za-z\s\-'\.]{2,60}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{2,40}$")


def _is_image_url(url: str) -> bool:
    try:
        path = urlparse(url).path.lower().rstrip("/")
        ext  = path.rsplit(".", 1)[-1] if "." in path else ""
        return ext in _IMAGE_EXTENSIONS
    except Exception:
        return False


def classify(raw: str) -> PivotType:
    s = raw.strip().strip('"').strip("'").strip()

    if _IPV4_RE.match(s):
        octets = [int(o) for o in s.split(".")]
        if all(0 <= o <= 255 for o in octets):
            return PivotType.IP_ADDRESS

    if _EMAIL_RE.match(s):
        return PivotType.EMAIL

    if _PHONE_RE.match(s):
        return PivotType.PHONE

    # VIN — exactly 17 valid chars, checked before plate
    if _VIN_RE.match(s) and len(s) == 17:
        return PivotType.VIN

    # Image URLs
    if s.startswith("http://") or s.startswith("https://"):
        if _is_image_url(s):
            return PivotType.IMAGE
        return PivotType.UNKNOWN

    if _DOMAIN_RE.match(s) and "." in s and " " not in s:
        return PivotType.DOMAIN

    if _NAME_RE.match(s) and " " in s:
        return PivotType.NAME

    # License plate — checked before username to catch numeric plates
    clean = re.sub(r"[\s\-]", "", s).upper()
    if 2 <= len(clean) <= 8 and re.match(r"^[A-Z0-9]+$", clean) \
            and not clean.isdigit():
        # Differentiate from username — plates are short and often
        # contain both letters AND digits in typical patterns
        has_letter = any(c.isalpha() for c in clean)
        has_digit  = any(c.isdigit() for c in clean)
        if has_letter and has_digit and len(clean) <= 8:
            return PivotType.LICENSE_PLATE

    if _USERNAME_RE.match(s):
        return PivotType.USERNAME

    return PivotType.UNKNOWN


def clean(raw: str) -> str:
    return raw.strip().strip('"').strip("'").strip()


def type_label(pt: PivotType) -> str:
    return {
        PivotType.IP_ADDRESS:    "IP Address",
        PivotType.EMAIL:         "Email Address",
        PivotType.PHONE:         "Phone Number",
        PivotType.DOMAIN:        "Domain",
        PivotType.IMAGE:         "Image URL",
        PivotType.NAME:          "Full Name",
        PivotType.USERNAME:      "Username",
        PivotType.VIN:           "VIN",
        PivotType.LICENSE_PLATE: "License Plate",
        PivotType.UNKNOWN:       "Unknown",
    }[pt]
