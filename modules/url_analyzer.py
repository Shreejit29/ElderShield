"""
ElderShield URL Analyzer

Analyzes URLs for structural scam/phishing indicators.

IMPORTANT:
This module does NOT prove that a URL is malicious or safe.

It only identifies suspicious characteristics such as:
- Dangerous schemes
- HTTP instead of HTTPS
- Raw IP addresses
- URL userinfo (@)
- Excessive subdomains
- URL shorteners
- Suspicious keywords
- Very long URLs
- Non-ASCII / IDN domains
- Suspicious ports
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


# ============================================================
# CONFIGURATION
# ============================================================

MAX_URL_LENGTH = 4096

SUSPICIOUS_SCHEMES = {
    "javascript",
    "data",
    "file",
    "vbscript",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "tiny.cc",
    "ow.ly",
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "kyc",
    "bank",
    "payment",
    "refund",
    "reward",
    "prize",
    "wallet",
    "password",
    "credential",
    "confirm",
    "unlock",
    "suspend",
    "blocked",
    "urgent",
}

SUSPICIOUS_PORTS = {
    21,
    22,
    23,
    25,
    110,
    143,
    445,
    3389,
    5900,
}


# ============================================================
# HELPERS
# ============================================================

def normalize_url(url: str) -> str:
    """
    Normalize basic whitespace around a URL.

    If no scheme is supplied, https:// is added for parsing.

    This function does NOT perform network access.
    """

    if not isinstance(url, str):
        raise TypeError("URL must be a string.")

    value = url.strip()

    if not value:
        return ""

    if "://" not in value:
        value = "https://" + value

    return value


def is_ip_address(hostname: str | None) -> bool:
    """
    Determine whether the hostname is a literal IPv4 or IPv6 address.
    """

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def contains_non_ascii(value: str | None) -> bool:
    """
    Check whether a string contains non-ASCII characters.
    """

    if not value:
        return False

    return any(
        ord(character) > 127
        for character in value
    )


def count_subdomains(hostname: str | None) -> int:
    """
    Count hostname labels before the registrable-looking domain.

    This is intentionally only a heuristic.
    """

    if not hostname:
        return 0

    labels = [
        label
        for label in hostname.split(".")
        if label
    ]

    if len(labels) <= 2:
        return 0

    return len(labels) - 2


def hostname_has_punycode(hostname: str | None) -> bool:
    """
    Detect xn-- Punycode labels.
    """

    if not hostname:
        return False

    return any(
        label.lower().startswith("xn--")
        for label in hostname.split(".")
    )


def find_suspicious_keywords(
    url: str,
) -> list[str]:
    """
    Find suspicious keywords appearing in the URL.

    This is only a signal. Legitimate websites can contain
    the same words.
    """

    lowered = url.lower()

    found = []

    for keyword in sorted(SUSPICIOUS_KEYWORDS):

        if keyword in lowered:
            found.append(keyword)

    return found


# ============================================================
# MAIN ANALYZER
# ============================================================

def analyze_url(url: str) -> dict:
    """
    Analyze a URL without making a network request.

    Returns a structured result containing:
        risk
        score
        domain
        scheme
        port
        reasons
        indicators
    """

    result = {
        "risk": "UNKNOWN",
        "score": 0,
        "domain": None,
        "scheme": None,
        "port": None,
        "reasons": [],
        "indicators": [],
        "normalized_url": None,
    }

    # --------------------------------------------------------
    # Basic validation
    # --------------------------------------------------------

    if not isinstance(url, str):

        result["reasons"].append(
            "URL must be text."
        )

        return result

    raw_url = url.strip()

    if not raw_url:

        result["reasons"].append(
            "No URL was provided."
        )

        return result

    if len(raw_url) > MAX_URL_LENGTH:

        result["risk"] = "HIGH RISK"
        result["score"] += 3

        result["reasons"].append(
            "The URL is unusually long."
        )

        result["indicators"].append(
            "very_long_url"
        )

        return result

    # --------------------------------------------------------
    # Normalize
    # --------------------------------------------------------

    try:

        normalized = normalize_url(raw_url)

        result["normalized_url"] = normalized

        parsed = urlsplit(normalized)

    except Exception:

        result["risk"] = "HIGH RISK"
        result["score"] += 3

        result["reasons"].append(
            "The URL could not be parsed safely."
        )

        result["indicators"].append(
            "invalid_url"
        )

        return result

    scheme = parsed.scheme.lower()

    hostname = (
        parsed.hostname.lower()
        if parsed.hostname
        else None
    )

    result["scheme"] = scheme
    result["domain"] = hostname

    # --------------------------------------------------------
    # Scheme
    # --------------------------------------------------------

    if scheme in SUSPICIOUS_SCHEMES:

        result["score"] += 10

        result["indicators"].append(
            "dangerous_scheme"
        )

        result["reasons"].append(
            f"The URL uses the potentially dangerous "
            f"'{scheme}:' scheme."
        )

    elif scheme not in {"http", "https"}:

        result["score"] += 5

        result["indicators"].append(
            "unusual_scheme"
        )

        result["reasons"].append(
            f"The URL uses an unusual scheme: {scheme}."
        )

    # --------------------------------------------------------
    # Missing hostname
    # --------------------------------------------------------

    if not hostname:

        result["score"] += 5

        result["indicators"].append(
            "missing_hostname"
        )

        result["reasons"].append(
            "The URL does not contain a normal hostname."
        )

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    if scheme == "http":

        result["score"] += 2

        result["indicators"].append(
            "http"
        )

        result["reasons"].append(
            "The website uses HTTP instead of HTTPS."
        )

    # --------------------------------------------------------
    # Raw IP address
    # --------------------------------------------------------

    if is_ip_address(hostname):

        result["score"] += 5

        result["indicators"].append(
            "raw_ip"
        )

        result["reasons"].append(
            "The website uses a raw IP address instead "
            "of a normal domain name."
        )

    # --------------------------------------------------------
    # User information in URL
    # --------------------------------------------------------

    if parsed.username is not None:

        result["score"] += 5

        result["indicators"].append(
            "userinfo"
        )

        result["reasons"].append(
            "The URL contains user-information syntax (@), "
            "which can be used to disguise the real destination."
        )

    # --------------------------------------------------------
    # Port
    # --------------------------------------------------------

    try:

        port = parsed.port

    except ValueError:

        port = None

        result["score"] += 3

        result["indicators"].append(
            "invalid_port"
        )

        result["reasons"].append(
            "The URL contains an invalid port."
        )

    result["port"] = port

    if port in SUSPICIOUS_PORTS:

        result["score"] += 3

        result["indicators"].append(
            "unusual_port"
        )

        result["reasons"].append(
            f"The URL uses port {port}, which is unusual "
            "for a normal public website."
        )

    # --------------------------------------------------------
    # Subdomains
    # --------------------------------------------------------

    subdomain_count = count_subdomains(
        hostname
    )

    if subdomain_count >= 3:

        result["score"] += 2

        result["indicators"].append(
            "many_subdomains"
        )

        result["reasons"].append(
            "The hostname contains many subdomain levels."
        )

    # --------------------------------------------------------
    # Non-ASCII / Punycode
    # --------------------------------------------------------

    if contains_non_ascii(hostname):

        result["score"] += 3

        result["indicators"].append(
            "non_ascii_domain"
        )

        result["reasons"].append(
            "The domain contains non-ASCII characters."
        )

    if hostname_has_punycode(hostname):

        result["score"] += 3

        result["indicators"].append(
            "punycode"
        )

        result["reasons"].append(
            "The domain contains Punycode."
        )

    # --------------------------------------------------------
    # URL shorteners
    # --------------------------------------------------------

    if hostname in SHORTENER_DOMAINS:

        result["score"] += 3

        result["indicators"].append(
            "url_shortener"
        )

        result["reasons"].append(
            "The URL uses a link-shortening service, "
            "so the final destination is hidden."
        )

    # --------------------------------------------------------
    # Suspicious keywords
    # --------------------------------------------------------

    keywords = find_suspicious_keywords(
        normalized
    )

    if keywords:

        # Cap this contribution so that many repeated keywords
        # don't dominate the entire risk calculation.
        keyword_score = min(
            len(keywords),
            4,
        )

        result["score"] += keyword_score

        result["indicators"].append(
            "suspicious_keywords"
        )

        result["reasons"].append(
            "The URL contains security, account, payment "
            "or urgency-related terms."
        )

        result["keyword_matches"] = keywords

    else:

        result["keyword_matches"] = []

    # --------------------------------------------------------
    # Long URL
    # --------------------------------------------------------

    if len(normalized) >= 250:

        result["score"] += 2

        result["indicators"].append(
            "long_url"
        )

        result["reasons"].append(
            "The URL is unusually long."
        )

    # --------------------------------------------------------
    # Risk classification
    # --------------------------------------------------------

    score = result["score"]

    if score >= 10:

        result["risk"] = "CRITICAL"

    elif score >= 7:

        result["risk"] = "HIGH RISK"

    elif score >= 3:

        result["risk"] = "CAUTION"

    else:

        result["risk"] = "SAFE"

    # --------------------------------------------------------
    # Important qualification
    # --------------------------------------------------------

    result["note"] = (
        "This is a structural URL assessment only. "
        "A low-risk result does not prove that the website "
        "is legitimate."
    )

    return result


# ============================================================
# CONVENIENCE FUNCTION
# ============================================================

def is_suspicious_url(url: str) -> bool:
    """
    Simple helper for other ElderShield modules.

    Returns True when the structural analysis produces
    HIGH RISK or CRITICAL.
    """

    result = analyze_url(url)

    return result["risk"] in {
        "HIGH RISK",
        "CRITICAL",
    }
