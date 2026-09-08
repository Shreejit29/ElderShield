"""
ElderShield Scam Knowledge Engine

Provides access to ElderShield's structured scam knowledge base.

This module does not make the final risk decision.
It supplies context to the case engine and intervention engine.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

KNOWLEDGE_FILE = (
    BASE_DIR / "data" / "india_scam_knowledge.json"
)


# ============================================================
# KNOWLEDGE LOADING
# ============================================================

def load_knowledge_base() -> dict[str, Any]:
    """
    Load the ElderShield scam knowledge base.

    Returns an empty dictionary if the file is missing or
    contains invalid JSON.
    """

    if not KNOWLEDGE_FILE.exists():
        return {}

    try:

        with KNOWLEDGE_FILE.open(
            "r",
            encoding="utf-8",
        ) as file:

            data = json.load(file)

        if isinstance(data, dict):
            return data

    except (
        OSError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):
        pass

    return {}


# ============================================================
# CATEGORY ACCESS
# ============================================================

def get_scam_categories() -> list[str]:
    """
    Return all scam-category identifiers.
    """

    knowledge = load_knowledge_base()

    return sorted(
        knowledge.keys()
    )


def get_scam_category(
    category: str | None,
) -> dict[str, Any] | None:
    """
    Return information for one scam category.
    """

    if not category:
        return None

    knowledge = load_knowledge_base()

    return knowledge.get(
        category
    )


# ============================================================
# CATEGORY SEARCH
# ============================================================

def search_categories(
    text: str,
) -> list[dict[str, Any]]:
    """
    Search the knowledge base for categories whose keywords
    appear in supplied text.

    This is intentionally a simple deterministic helper.
    It does not replace the main case engine.
    """

    if not isinstance(text, str):
        return []

    normalized_text = text.lower()

    knowledge = load_knowledge_base()

    matches = []

    for category_id, category in knowledge.items():

        if not isinstance(category, dict):
            continue

        keywords = category.get(
            "keywords",
            [],
        )

        if not isinstance(keywords, list):
            continue

        matched_keywords = []

        for keyword in keywords:

            if not isinstance(keyword, str):
                continue

            if keyword.lower() in normalized_text:

                matched_keywords.append(
                    keyword
                )

        if matched_keywords:

            matches.append(
                {
                    "category": category_id,
                    "name": category.get(
                        "name",
                        category_id,
                    ),
                    "matched_keywords": (
                        matched_keywords
                    ),
                }
            )

    return matches


# ============================================================
# CATEGORY GUIDANCE
# ============================================================

def get_category_guidance(
    category: str,
) -> dict[str, Any]:
    """
    Return a normalized guidance structure for a scam category.
    """

    entry = get_scam_category(
        category
    )

    if not entry:

        return {
            "category": category,
            "found": False,
            "name": category,
            "warning": "",
            "indicators": [],
            "dangerous_actions": [],
            "recommended_actions": [],
        }

    return {
        "category": category,
        "found": True,
        "name": entry.get(
            "name",
            category,
        ),
        "warning": entry.get(
            "warning",
            "",
        ),
        "indicators": entry.get(
            "indicators",
            [],
        ),
        "dangerous_actions": entry.get(
            "dangerous_actions",
            [],
        ),
        "recommended_actions": entry.get(
            "recommended_actions",
            [],
        ),
    }


# ============================================================
# DANGEROUS ACTION SEARCH
# ============================================================

def find_dangerous_actions(
    text: str,
) -> list[str]:
    """
    Identify potentially dangerous actions mentioned in text.

    Examples:
    - OTP
    - UPI PIN
    - password
    - remote access
    - money transfer

    This is a supporting signal only.
    """

    if not isinstance(text, str):
        return []

    normalized_text = text.lower()

    knowledge = load_knowledge_base()

    actions = set()

    for category in knowledge.values():

        if not isinstance(category, dict):
            continue

        dangerous_actions = category.get(
            "dangerous_actions",
            [],
        )

        if not isinstance(
            dangerous_actions,
            list,
        ):
            continue

        for action in dangerous_actions:

            if not isinstance(action, str):
                continue

            if action.lower() in normalized_text:

                actions.add(action)

    return sorted(actions)


# ============================================================
# INDICATOR SEARCH
# ============================================================

def find_indicators(
    text: str,
) -> list[str]:
    """
    Search all known scam indicators in supplied text.
    """

    if not isinstance(text, str):
        return []

    normalized_text = text.lower()

    knowledge = load_knowledge_base()

    matches = set()

    for category in knowledge.values():

        if not isinstance(category, dict):
            continue

        indicators = category.get(
            "indicators",
            [],
        )

        if not isinstance(
            indicators,
            list,
        ):
            continue

        for indicator in indicators:

            if not isinstance(indicator, str):
                continue

            if indicator.lower() in normalized_text:

                matches.add(indicator)

    return sorted(matches)


# ============================================================
# CATEGORY RECOMMENDATION
# ============================================================

def get_primary_category(
    text: str,
) -> str | None:
    """
    Return the first matching scam category.

    This is intentionally conservative and simple.

    The final case engine should be responsible for combining
    multiple categories and evidence sources.
    """

    matches = search_categories(
        text
    )

    if not matches:
        return None

    return matches[0]["category"]
