"""
ElderShield Brand / Organization Impersonation Checker

Detects possible impersonation of known organizations by
comparing organization names mentioned in text with URLs/domains.

IMPORTANT:
- A matching domain does NOT prove that a message is legitimate.
- A mismatch is a strong warning signal when the organization
  identity is otherwise clear.
- This module performs local analysis only.
- It does not open or fetch websites.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(
    __file__
).resolve().parent.parent

OFFICIAL_DOMAINS_FILE = (
    BASE_DIR
    / "data"
    / "official_domains.json"
)


# ============================================================
# DOMAIN HELPERS
# ============================================================

def normalize_domain(
    domain: str,
) -> str:
    """
    Normalize a domain for comparison.
    """

    value = str(
        domain or ""
    ).strip().lower()

    if "://" in value:

        try:

            value = urlparse(
                value
            ).hostname or ""

        except Exception:

            value = ""

    value = value.strip(
        "."
    )

    if value.startswith(
        "www."
    ):

        value = value[4:]

    return value


def extract_domain(
    url: str,
) -> str:
    """
    Extract hostname from a URL without making a network request.
    """

    value = str(
        url or ""
    ).strip()

    if not value:
        return ""

    try:

        parsed = urlparse(
            value
            if "://" in value
            else f"https://{value}"
        )

        return normalize_domain(
            parsed.hostname or ""
        )

    except Exception:

        return ""


def domain_matches(
    actual_domain: str,
    official_domain: str,
) -> bool:
    """
    Determine whether actual_domain is the official domain
    or a legitimate subdomain of it.
    """

    actual = normalize_domain(
        actual_domain
    )

    official = normalize_domain(
        official_domain
    )

    if not actual or not official:
        return False

    return (
        actual == official
        or actual.endswith(
            "." + official
        )
    )


# ============================================================
# OFFICIAL DOMAIN DATABASE
# ============================================================

def load_official_domains() -> dict[str, Any]:
    """
    Load the local official-domain database.
    """

    try:

        with open(
            OFFICIAL_DOMAINS_FILE,
            "r",
            encoding="utf-8",
        ) as file:

            data = json.load(
                file
            )

        if isinstance(
            data,
            dict,
        ):

            return data

    except Exception:
        pass

    return {}


def get_organization_record(
    organization: str,
) -> dict[str, Any] | None:
    """
    Find an organization in the local database.

    Supports both exact IDs and common aliases.
    """

    data = load_official_domains()

    normalized = re.sub(
        r"[^a-z0-9]+",
        "_",
        str(
            organization or ""
        ).lower(),
    ).strip("_")

    if not normalized:
        return None

    if normalized in data:

        record = data[
            normalized
        ]

        if isinstance(
            record,
            dict,
        ):

            return record

    # --------------------------------------------------------
    # Alias matching
    # --------------------------------------------------------

    aliases = {
        "state_bank_of_india": "sbi",
        "state_bank_india": "sbi",
        "sbi_bank": "sbi",
        "income_tax": "incometax",
        "income_tax_department": "incometax",
        "reserve_bank_of_india": "rbi",
        "reserve_bank": "rbi",
        "aadhaar": "uidai",
        "aadhaar": "uidai",
        "india_post": "india_post",
        "indian_post": "india_post",
        "post_office": "india_post",
        "railway": "irctc",
        "indian_railways": "irctc",
        "epf": "epfindia",
        "epfo": "epfindia",
        "digilocker": "digilocker",
    }

    mapped = aliases.get(
        normalized
    )

    if mapped and mapped in data:

        record = data[
            mapped
        ]

        if isinstance(
            record,
            dict,
        ):

            return record

    # --------------------------------------------------------
    # Name-field matching
    # --------------------------------------------------------

    for key, record in data.items():

        if not isinstance(
            record,
            dict,
        ):
            continue

        name = str(
            record.get(
                "name",
                "",
            )
        ).lower()

        compact_name = re.sub(
            r"[^a-z0-9]+",
            "_",
            name,
        ).strip("_")

        if normalized == compact_name:

            return record

    return None


# ============================================================
# ORGANIZATION EXTRACTION
# ============================================================

KNOWN_ORGANIZATION_NAMES = {
    "sbi": "sbi",
    "state bank of india": "sbi",
    "state bank": "sbi",
    "rbi": "rbi",
    "reserve bank of india": "rbi",
    "income tax": "incometax",
    "income tax department": "incometax",
    "uidai": "uidai",
    "aadhaar": "uidai",
    "india post": "india_post",
    "indian post": "india_post",
    "irctc": "irctc",
    "indian railways": "irctc",
    "epfo": "epfindia",
    "epfindia": "epfindia",
    "digilocker": "digilocker",
}


def detect_organizations(
    text: str,
) -> list[str]:
    """
    Detect known organizations mentioned in text.
    """

    value = str(
        text or ""
    ).lower()

    found: list[str] = []

    for phrase, organization_id in KNOWN_ORGANIZATION_NAMES.items():

        if phrase in value:

            if organization_id not in found:

                found.append(
                    organization_id
                )

    return found


# ============================================================
# IMPERSONATION ANALYSIS
# ============================================================

def check_brand_impersonation(
    organization: str,
    url: str,
) -> dict[str, Any]:
    """
    Compare a claimed organization with a supplied URL.

    Returns a conservative result.
    """

    organization_value = str(
        organization or ""
    ).strip()

    url_value = str(
        url or ""
    ).strip()

    if not organization_value:

        return {
            "status": "UNKNOWN",
            "organization": "",
            "official_domain": "",
            "actual_domain": extract_domain(
                url_value
            ),
            "reason": (
                "No organization was supplied for comparison."
            ),
        }

    record = get_organization_record(
        organization_value
    )

    actual_domain = extract_domain(
        url_value
    )

    if record is None:

        return {
            "status": "UNKNOWN",
            "organization": organization_value,
            "official_domain": "",
            "actual_domain": actual_domain,
            "reason": (
                "The organization is not present in ElderShield's "
                "conservative official-domain database."
            ),
        }

    official_domain = normalize_domain(
        str(
            record.get(
                "official_domain",
                record.get(
                    "domain",
                    "",
                ),
            )
        )
    )

    if not actual_domain:

        return {
            "status": "UNKNOWN",
            "organization": organization_value,
            "official_domain": official_domain,
            "actual_domain": "",
            "reason": (
                "No usable URL/domain was supplied."
            ),
        }

    if not official_domain:

        return {
            "status": "UNKNOWN",
            "organization": organization_value,
            "official_domain": "",
            "actual_domain": actual_domain,
            "reason": (
                "No official domain is recorded for this organization."
            ),
        }

    if domain_matches(
        actual_domain,
        official_domain,
    ):

        return {
            "status": "MATCH",
            "organization": organization_value,
            "official_domain": official_domain,
            "actual_domain": actual_domain,
            "reason": (
                "The supplied domain matches the organization's "
                "recorded official domain."
            ),
            "warning": (
                "A domain match does not prove that the entire "
                "message or request is legitimate."
            ),
        }

    return {
        "status": "MISMATCH",
        "organization": organization_value,
        "official_domain": official_domain,
        "actual_domain": actual_domain,
        "reason": (
            "The supplied domain does not match the organization's "
            "recorded official domain."
        ),
        "warning": (
            "This is a strong impersonation warning. "
            "Do not enter credentials or make payments."
        ),
    }


# ============================================================
# TEXT + URL COMBINED CHECK
# ============================================================

def analyze_brand_impersonation(
    text: str,
    url: str = "",
) -> dict[str, Any]:
    """
    Detect organizations in text and compare them with a URL.

    If multiple organizations are mentioned, each is checked.
    """

    organizations = detect_organizations(
        text
    )

    if not organizations:

        return {
            "organizations": [],
            "checks": [],
            "has_mismatch": False,
            "has_match": False,
            "risk_hint": "UNKNOWN",
        }

    checks: list[dict[str, Any]] = []

    for organization in organizations:

        result = check_brand_impersonation(
            organization,
            url,
        )

        checks.append(
            result
        )

    has_mismatch = any(
        result.get("status") == "MISMATCH"
        for result in checks
    )

    has_match = any(
        result.get("status") == "MATCH"
        for result in checks
    )

    if has_mismatch:

        risk_hint = "HIGH RISK"

    elif has_match:

        risk_hint = "CAUTION"

    else:

        risk_hint = "UNKNOWN"

    return {
        "organizations": organizations,
        "checks": checks,
        "has_mismatch": has_mismatch,
        "has_match": has_match,
        "risk_hint": risk_hint,
    }
