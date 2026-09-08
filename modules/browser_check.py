"""
ElderShield Browser Safety Checks

Provides a conservative browser/link safety layer.

This module:
- Performs local URL inspection.
- Uses the existing URL analyzer when available.
- Detects suspicious login/payment paths.
- Detects URL fragments that commonly appear in phishing links.
- Does not automatically open websites.
- Does not execute JavaScript.
- Does not download files.

Network access, when required, must pass through safe_url.py.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote, urlparse

from modules.url_analyzer import analyze_url
from modules.validators import validate_url


# ============================================================
# CONSTANTS
# ============================================================

MAX_URL_LENGTH = 4_000


SUSPICIOUS_PATH_TERMS = (
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "kyc",
    "payment",
    "pay",
    "refund",
    "wallet",
    "banking",
    "password",
    "otp",
    "confirm",
    "activate",
    "unlock",
)


SUSPICIOUS_QUERY_TERMS = (
    "login",
    "verify",
    "verification",
    "password",
    "passcode",
    "otp",
    "pin",
    "cvv",
    "payment",
    "upi",
    "account",
    "kyc",
)


PHISHING_KEYWORDS = (
    "free",
    "reward",
    "prize",
    "refund",
    "urgent",
    "claim",
    "verify",
    "security",
    "suspended",
    "blocked",
    "winner",
)


# ============================================================
# URL PARTS
# ============================================================

def extract_url_parts(
    url: Any,
) -> dict[str, str]:
    """
    Extract basic URL components without making a network request.
    """

    value = str(
        url or ""
    ).strip()

    try:

        parsed = urlparse(
            value
        )

    except Exception:

        return {
            "scheme": "",
            "hostname": "",
            "path": "",
            "query": "",
            "fragment": "",
        }

    return {
        "scheme": parsed.scheme.lower(),
        "hostname": (
            parsed.hostname or ""
        ).lower(),
        "path": unquote(
            parsed.path or ""
        ),
        "query": unquote(
            parsed.query or ""
        ),
        "fragment": unquote(
            parsed.fragment or ""
        ),
    }


# ============================================================
# PATH ANALYSIS
# ============================================================

def find_suspicious_path_terms(
    url: Any,
) -> list[str]:
    """
    Find suspicious terms in the URL path.
    """

    parts = extract_url_parts(
        url
    )

    path = parts[
        "path"
    ].lower()

    return [
        term
        for term in SUSPICIOUS_PATH_TERMS
        if term in path
    ]


def find_suspicious_query_terms(
    url: Any,
) -> list[str]:
    """
    Find suspicious terms in the query string.

    Query terms are not proof of phishing.
    """

    parts = extract_url_parts(
        url
    )

    query = parts[
        "query"
    ].lower()

    return [
        term
        for term in SUSPICIOUS_QUERY_TERMS
        if term in query
    ]


def find_phishing_keywords(
    url: Any,
) -> list[str]:
    """
    Find common phishing-related keywords anywhere in the URL.
    """

    value = str(
        url or ""
    ).lower()

    return [
        keyword
        for keyword in PHISHING_KEYWORDS
        if keyword in value
    ]


# ============================================================
# URL CHARACTERISTICS
# ============================================================

def has_http_scheme(
    url: Any,
) -> bool:
    """
    Return True when the URL explicitly uses HTTP.
    """

    parts = extract_url_parts(
        url
    )

    return parts[
        "scheme"
    ] == "http"


def has_https_scheme(
    url: Any,
) -> bool:
    """
    Return True when the URL explicitly uses HTTPS.
    """

    parts = extract_url_parts(
        url
    )

    return parts[
        "scheme"
    ] == "https"


def has_encoded_content(
    url: Any,
) -> bool:
    """
    Detect URL percent-encoding.

    Encoding is not inherently malicious, but can make
    inspection harder.
    """

    value = str(
        url or ""
    )

    return bool(
        re.search(
            r"%[0-9A-Fa-f]{2}",
            value,
        )
    )


# ============================================================
# BROWSER ANALYSIS
# ============================================================

def analyze_browser_url(
    url: Any,
) -> dict[str, Any]:
    """
    Perform a conservative browser safety assessment.

    This function performs NO network request.
    """

    value = str(
        url or ""
    ).strip()

    validation = validate_url(
        value
    )

    if not validation.get(
        "valid",
        False,
    ):

        return {
            "risk": "HIGH",
            "url": value[:MAX_URL_LENGTH],
            "reasons": [
                validation.get(
                    "reason",
                    "Invalid URL.",
                )
            ],
            "indicators": [
                "invalid_url"
            ],
            "recommended_actions": [
                "Do not open the supplied URL.",
                "Ask the sender for the official website instead.",
            ],
        }

    normalized_url = validation[
        "normalized"
    ]

    structural = analyze_url(
        normalized_url
    )

    path_terms = find_suspicious_path_terms(
        normalized_url
    )

    query_terms = find_suspicious_query_terms(
        normalized_url
    )

    phishing_keywords = find_phishing_keywords(
        normalized_url
    )

    parts = extract_url_parts(
        normalized_url
    )

    indicators: list[str] = []
    reasons: list[str] = []

    # --------------------------------------------------------
    # Existing structural analyzer
    # --------------------------------------------------------

    structural_risk = str(
        structural.get(
            "risk",
            "UNKNOWN",
        )
    ).upper()

    if structural_risk in (
        "HIGH",
        "CRITICAL",
    ):

        indicators.append(
            "suspicious_url_structure"
        )

        reasons.extend(
            structural.get(
                "reasons",
                [],
            )
        )

    elif structural_risk == "CAUTION":

        indicators.append(
            "url_requires_caution"
        )

        reasons.extend(
            structural.get(
                "reasons",
                [],
            )
        )

    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    if has_http_scheme(
        normalized_url
    ):

        indicators.append(
            "unencrypted_http"
        )

        reasons.append(
            "The link uses HTTP instead of HTTPS."
        )

    # --------------------------------------------------------
    # Suspicious path
    # --------------------------------------------------------

    if path_terms:

        indicators.append(
            "suspicious_path"
        )

        reasons.append(
            "The URL contains login, verification, payment "
            "or account-related path terms."
        )

    # --------------------------------------------------------
    # Suspicious query
    # --------------------------------------------------------

    if query_terms:

        indicators.append(
            "suspicious_query"
        )

        reasons.append(
            "The URL contains parameters associated with "
            "login, verification or payment activity."
        )

    # --------------------------------------------------------
    # Phishing keywords
    # --------------------------------------------------------

    if phishing_keywords:

        indicators.append(
            "phishing_keywords"
        )

        reasons.append(
            "The URL contains words commonly used in "
            "social-engineering or phishing messages."
        )

    # --------------------------------------------------------
    # Encoding
    # --------------------------------------------------------

    if has_encoded_content(
        normalized_url
    ):

        indicators.append(
            "encoded_url_content"
        )

        reasons.append(
            "The URL contains encoded characters, so inspect "
            "the destination carefully."
        )

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    if structural_risk == "CRITICAL":

        risk = "CRITICAL"

    elif structural_risk == "HIGH":

        risk = "HIGH"

    elif (
        "suspicious_url_structure" in indicators
        and (
            path_terms
            or query_terms
        )
    ):

        risk = "HIGH"

    elif len(indicators) >= 3:

        risk = "HIGH"

    elif (
        path_terms
        or query_terms
        or phishing_keywords
    ):

        risk = "CAUTION"

    elif structural_risk == "CAUTION":

        risk = "CAUTION"

    else:

        risk = "UNKNOWN"

    # --------------------------------------------------------
    # Actions
    # --------------------------------------------------------

    recommended_actions = [
        "Do not enter passwords, OTPs, UPI PINs or card details into an unexpected website.",
        "Open the official app or type the official website address yourself.",
        "Do not download software because a website asks you to.",
    ]

    if risk in (
        "HIGH",
        "CRITICAL",
    ):

        recommended_actions.insert(
            0,
            "Do not open or interact with this link until it has been independently verified.",
        )

    return {
        "risk": risk,
        "url": normalized_url,
        "hostname": parts[
            "hostname"
        ],
        "scheme": parts[
            "scheme"
        ],
        "path_terms": path_terms,
        "query_terms": query_terms,
        "phishing_keywords": phishing_keywords,
        "indicators": list(
            dict.fromkeys(
                indicators
            )
        ),
        "reasons": list(
            dict.fromkeys(
                reasons
            )
        ),
        "structural_analysis": structural,
        "recommended_actions": list(
            dict.fromkeys(
                recommended_actions
            )
        ),
        "network_checked": False,
        "disclaimer": (
            "This check does not prove that a website is malicious "
            "or legitimate. Network access, if later required, "
            "must use ElderShield's SSRF-safe network boundary."
        ),
    }


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "MAX_URL_LENGTH",
    "extract_url_parts",
    "find_suspicious_path_terms",
    "find_suspicious_query_terms",
    "find_phishing_keywords",
    "has_http_scheme",
    "has_https_scheme",
    "has_encoded_content",
    "analyze_browser_url",
]
