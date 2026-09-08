"""
ElderShield Incident Management

Creates privacy-conscious incident records from ElderShield
analysis results.

An incident record is a structured summary of what happened.

IMPORTANT:
- Never store passwords.
- Never store OTPs.
- Never store UPI PINs or ATM PINs.
- Never store raw audio or image data.
- Never store complete sensitive messages by default.
- Incident records are summaries, not legal proof.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


# ============================================================
# CONSTANTS
# ============================================================

MAX_REASONS = 20
MAX_ACTIONS = 20
MAX_CATEGORIES = 10
MAX_CHANNELS = 10
MAX_DANGEROUS_ACTIONS = 20


# ============================================================
# HELPERS
# ============================================================

def _string_list(
    value: Any,
    limit: int,
) -> list[str]:
    """
    Convert a value into a clean bounded string list.
    """

    if not isinstance(
        value,
        list,
    ):

        return []

    result: list[str] = []

    for item in value:

        text = str(
            item or ""
        ).strip()

        if not text:

            continue

        if text not in result:

            result.append(
                text
            )

        if len(result) >= limit:

            break

    return result


def _risk(
    value: Any,
) -> str:
    """
    Normalize risk.
    """

    value = str(
        value or "UNKNOWN"
    ).upper().strip()

    allowed = {
        "SAFE",
        "CAUTION",
        "HIGH",
        "CRITICAL",
        "UNKNOWN",
    }

    if value not in allowed:

        return "UNKNOWN"

    return value


# ============================================================
# INCIDENT ID
# ============================================================

def generate_incident_id() -> str:
    """
    Generate a non-sensitive incident identifier.
    """

    return (
        "ES-"
        + uuid4().hex[:12].upper()
    )


# ============================================================
# INCIDENT CREATION
# ============================================================

def create_incident(
    case_result: dict[str, Any] | None,
    *,
    source: str = "analysis",
) -> dict[str, Any]:
    """
    Create a privacy-conscious incident record.

    Only structured safety information is copied from the case.
    """

    case = (
        case_result
        if isinstance(
            case_result,
            dict,
        )
        else {}
    )

    risk = _risk(
        case.get(
            "risk",
            "UNKNOWN",
        )
    )

    reasons = _string_list(
        case.get(
            "reasons",
            [],
        ),
        MAX_REASONS,
    )

    actions = _string_list(
        case.get(
            "actions",
            case.get(
                "recommended_actions",
                [],
            ),
        ),
        MAX_ACTIONS,
    )

    categories = _string_list(
        case.get(
            "categories",
            [],
        ),
        MAX_CATEGORIES,
    )

    channels = _string_list(
        case.get(
            "channels",
            [],
        ),
        MAX_CHANNELS,
    )

    dangerous_actions = _string_list(
        case.get(
            "dangerous_actions",
            [],
        ),
        MAX_DANGEROUS_ACTIONS,
    )

    headline = str(
        case.get(
            "headline",
            "",
        )
        or ""
    ).strip()

    summary = str(
        case.get(
            "summary",
            "",
        )
        or ""
    ).strip()

    return {
        "incident_id": generate_incident_id(),

        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "source": str(
            source or "analysis"
        ).strip()[:100],

        "risk": risk,

        "headline": headline[:300],

        "summary": summary[:1000],

        "reasons": reasons,

        "actions": actions,

        "categories": categories,

        "channels": channels,

        "dangerous_actions": dangerous_actions,

        "evidence_count": int(
            case.get(
                "evidence_count",
                0,
            )
            or 0
        ),

        "strong_signal_count": int(
            case.get(
                "strong_signal_count",
                0,
            )
            or 0
        ),

        "critical_signal_count": int(
            case.get(
                "critical_signal_count",
                0,
            )
            or 0
        ),

        "privacy": {
            "raw_message_stored": False,
            "raw_audio_stored": False,
            "raw_image_stored": False,
            "credentials_stored": False,
        },
    }


# ============================================================
# INCIDENT STATUS
# ============================================================

def incident_requires_action(
    incident: dict[str, Any] | None,
) -> bool:
    """
    Determine whether an incident requires user action.
    """

    if not isinstance(
        incident,
        dict,
    ):

        return False

    risk = _risk(
        incident.get(
            "risk",
            "UNKNOWN",
        )
    )

    return risk in {
        "CAUTION",
        "HIGH",
        "CRITICAL",
    }


def incident_is_critical(
    incident: dict[str, Any] | None,
) -> bool:
    """
    Return True when the incident is critical.
    """

    if not isinstance(
        incident,
        dict,
    ):

        return False

    return (
        _risk(
            incident.get(
                "risk",
                "UNKNOWN",
            )
        )
        == "CRITICAL"
    )


# ============================================================
# SAFE EXPORT
# ============================================================

def incident_summary(
    incident: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Produce a smaller summary suitable for UI/history.
    """

    if not isinstance(
        incident,
        dict,
    ):

        return {
            "incident_id": "",
            "risk": "UNKNOWN",
            "headline": "",
            "summary": "",
        }

    return {
        "incident_id": str(
            incident.get(
                "incident_id",
                "",
            )
        ),

        "created_at": str(
            incident.get(
                "created_at",
                "",
            )
        ),

        "risk": _risk(
            incident.get(
                "risk",
                "UNKNOWN",
            )
        ),

        "headline": str(
            incident.get(
                "headline",
                "",
            )
        )[:300],

        "summary": str(
            incident.get(
                "summary",
                "",
            )
        )[:500],
    }


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "generate_incident_id",
    "create_incident",
    "incident_requires_action",
    "incident_is_critical",
    "incident_summary",
]
