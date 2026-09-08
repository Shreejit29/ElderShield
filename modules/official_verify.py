"""
ElderShield Official Organization Verification

Compares an organization claim with a conservative registry of
known official domains.

IMPORTANT:
A matching domain does NOT prove that a caller or website is safe.

A mismatch is a useful warning signal, but the registry itself
must be maintained carefully.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

OFFICIAL_DOMAINS_FILE = (
    BASE_DIR / "data" / "official_domains.json"
)


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_domain(
    domain: str | None,
) -> str:
    """
    Normalize a domain for comparison.

    Removes:
    - surrounding whitespace
    - protocol
    - path
    - query
    - fragment
    - leading www.
    - trailing dot
    """

    if not domain:
        return ""

    value = str(domain).strip().lower()

    value = re.sub(
        r"^[a-z][a-z0-9+.-]*://",
        "",
        value,
    )

    value = value.split("/", 1)[0]
    value = value.split("?", 1)[0]
    value = value.split("#", 1)[0]

    value = value.rstrip(".")

    if value.startswith("www."):
        value = value[4:]

    return value


def normalize_organization(
    organization: str | None,
) -> str:
    """
    Normalize an organization name for registry lookup.
    """

    if not organization:
        return ""

    value = str(organization).strip().lower()

    value = re.sub(
        r"[^a-z0-9]+",
        "_",
        value,
    )

    return value.strip("_")


# ============================================================
# REGISTRY LOADING
# ============================================================

def load_official_domains() -> dict[str, Any]:
    """
    Load the official-domain registry.

    Returns an empty registry if the file does not exist or
    contains invalid JSON.
    """

    if not OFFICIAL_DOMAINS_FILE.exists():
        return {}

    try:

        with OFFICIAL_DOMAINS_FILE.open(
            "r",
            encoding="utf-8",
        ) as file:

            data = json.load(file)

        if not isinstance(data, dict):
            return {}

        return data

    except (
        OSError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):

        return {}


# ============================================================
# DOMAIN MATCHING
# ============================================================

def domain_matches(
    supplied_domain: str,
    official_domain: str,
) -> bool:
    """
    Determine whether a supplied domain is the official domain
    or a subdomain of the official domain.

    Example:

        supplied:
            portal.example.gov.in

        official:
            example.gov.in

        result:
            True

    But:

        evil-example.gov.in

    does NOT match:

        example.gov.in
    """

    supplied = normalize_domain(
        supplied_domain
    )

    official = normalize_domain(
        official_domain
    )

    if not supplied or not official:
        return False

    if supplied == official:
        return True

    return supplied.endswith(
        "." + official
    )


# ============================================================
# ORGANIZATION LOOKUP
# ============================================================

def get_official_domains_for_organization(
    organization: str,
) -> list[str]:
    """
    Return registered official domains for an organization.
    """

    registry = load_official_domains()

    key = normalize_organization(
        organization
    )

    entry = registry.get(key)

    if entry is None:
        return []

    if isinstance(entry, list):

        return [
            normalize_domain(item)
            for item in entry
            if isinstance(item, str)
        ]

    if isinstance(entry, dict):

        domains = entry.get(
            "domains",
            [],
        )

        if isinstance(domains, list):

            return [
                normalize_domain(item)
                for item in domains
                if isinstance(item, str)
            ]

    return []


# ============================================================
# VERIFICATION
# ============================================================

def verify_organization(
    organization: str | None,
    domain: str | None,
) -> dict:
    """
    Compare a claimed organization against a supplied domain.

    Returns a structured verification result.
    """

    result = {
        "organization": organization,
        "domain": normalize_domain(domain),
        "status": "UNKNOWN",
        "message": "",
        "official_domains": [],
    }

    if not organization:

        result["message"] = (
            "No organization was identified."
        )

        return result

    if not domain:

        result["message"] = (
            "No domain was provided for verification."
        )

        return result

    official_domains = (
        get_official_domains_for_organization(
            organization
        )
    )

    result["official_domains"] = official_domains

    if not official_domains:

        result["status"] = "UNKNOWN"

        result["message"] = (
            "ElderShield does not have a verified domain "
            "entry for this organization in its current registry."
        )

        return result

    supplied_domain = normalize_domain(
        domain
    )

    for official_domain in official_domains:

        if domain_matches(
            supplied_domain,
            official_domain,
        ):

            result["status"] = "MATCH"

            result["message"] = (
                f"The supplied domain matches the registered "
                f"domain for {organization}."
            )

            result["matched_domain"] = (
                official_domain
            )

            result["warning"] = (
                "A domain match does not prove that the caller, "
                "message or website is legitimate."
            )

            return result

    # No match.
    result["status"] = "MISMATCH"

    result["message"] = (
        f"The supplied domain does not match the known "
        f"official domain(s) for {organization}."
    )

    result["warning"] = (
        "This is a strong reason to be cautious. "
        "Open the organization's official app or website "
        "yourself instead of using the supplied link."
    )

    return result


# ============================================================
# SIMPLE HELPERS
# ============================================================

def is_official_domain(
    organization: str,
    domain: str,
) -> bool:
    """
    Return True only when the domain matches a registered
    official domain.
    """

    result = verify_organization(
        organization,
        domain,
    )

    return result["status"] == "MATCH"


def is_domain_mismatch(
    organization: str,
    domain: str,
) -> bool:
    """
    Return True when the organization is known but the domain
    does not match its registered domains.
    """

    result = verify_organization(
        organization,
        domain,
    )

    return result["status"] == "MISMATCH"
