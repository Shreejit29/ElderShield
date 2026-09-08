"""
ElderShield Safe Report Export

Creates privacy-conscious text and JSON exports from an incident.

Exports contain structured safety information only.

They do NOT intentionally include:
- Passwords
- OTPs
- UPI PINs
- ATM PINs
- CVV/CVC
- Raw audio
- Raw images
- Full raw messages
"""

from __future__ import annotations

import json
from typing import Any

from modules.logging_utils import redact_for_log


# ============================================================
# CONSTANTS
# ============================================================

MAX_EXPORT_TEXT = 10_000
MAX_LIST_ITEMS = 20


# ============================================================
# HELPERS
# ============================================================

def _clean_string(
    value: Any,
    limit: int = 1000,
) -> str:
    """
    Convert a value into a bounded privacy-conscious string.
    """

    value = redact_for_log(
        value,
        limit,
    )

    return value.strip()


def _clean_list(
    value: Any,
) -> list[str]:
    """
    Convert a list into bounded safe strings.
    """

    if not isinstance(
        value,
        list,
    ):

        return []

    result: list[str] = []

    for item in value:

        cleaned = _clean_string(
            item,
            500,
        )

        if not cleaned:

            continue

        if cleaned not in result:

            result.append(
                cleaned
            )

        if len(result) >= MAX_LIST_ITEMS:

            break

    return result


# ============================================================
# INCIDENT SANITIZATION
# ============================================================

def sanitize_incident(
    incident: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Convert an incident into an export-safe structure.
    """

    if not isinstance(
        incident,
        dict,
    ):

        return {
            "incident_id": "",
            "created_at": "",
            "risk": "UNKNOWN",
            "headline": "",
            "summary": "",
            "reasons": [],
            "actions": [],
            "categories": [],
            "channels": [],
            "dangerous_actions": [],
        }

    safe = {
        "incident_id": _clean_string(
            incident.get(
                "incident_id",
                "",
            ),
            100,
        ),

        "created_at": _clean_string(
            incident.get(
                "created_at",
                "",
            ),
            100,
        ),

        "source": _clean_string(
            incident.get(
                "source",
                "analysis",
            ),
            100,
        ),

        "risk": _clean_string(
            incident.get(
                "risk",
                "UNKNOWN",
            ),
            30,
        ).upper(),

        "headline": _clean_string(
            incident.get(
                "headline",
                "",
            ),
            300,
        ),

        "summary": _clean_string(
            incident.get(
                "summary",
                "",
            ),
            1000,
        ),

        "reasons": _clean_list(
            incident.get(
                "reasons",
                [],
            )
        ),

        "actions": _clean_list(
            incident.get(
                "actions",
                [],
            )
        ),

        "categories": _clean_list(
            incident.get(
                "categories",
                [],
            )
        ),

        "channels": _clean_list(
            incident.get(
                "channels",
                [],
            )
        ),

        "dangerous_actions": _clean_list(
            incident.get(
                "dangerous_actions",
                [],
            )
        ),
    }

    # Keep evidence counts but never copy raw evidence.
    for key in (
        "evidence_count",
        "strong_signal_count",
        "critical_signal_count",
    ):

        try:

            safe[key] = max(
                0,
                int(
                    incident.get(
                        key,
                        0,
                    )
                    or 0
                ),
            )

        except Exception:

            safe[key] = 0

    safe["privacy"] = {
        "raw_message_stored": False,
        "raw_audio_stored": False,
        "raw_image_stored": False,
        "credentials_stored": False,
    }

    return safe


# ============================================================
# JSON EXPORT
# ============================================================

def incident_to_json(
    incident: dict[str, Any] | None,
) -> str:
    """
    Convert an incident into formatted JSON.
    """

    safe = sanitize_incident(
        incident
    )

    return json.dumps(
        safe,
        indent=2,
        ensure_ascii=False,
    )


# ============================================================
# TEXT EXPORT
# ============================================================

def incident_to_text(
    incident: dict[str, Any] | None,
) -> str:
    """
    Create a human-readable incident report.
    """

    safe = sanitize_incident(
        incident
    )

    lines: list[str] = []

    lines.append(
        "ELDERSHIELD SAFETY INCIDENT REPORT"
    )

    lines.append(
        "=" * 40
    )

    lines.append(
        f"Incident ID: {safe['incident_id']}"
    )

    lines.append(
        f"Date: {safe['created_at']}"
    )

    lines.append(
        f"Risk: {safe['risk']}"
    )

    if safe["headline"]:

        lines.append(
            f"Headline: {safe['headline']}"
        )

    if safe["summary"]:

        lines.append(
            ""
        )

        lines.append(
            "Summary:"
        )

        lines.append(
            safe["summary"]
        )

    if safe["categories"]:

        lines.append(
            ""
        )

        lines.append(
            "Possible scam categories:"
        )

        for item in safe["categories"]:

            lines.append(
                f"- {item}"
            )

    if safe["channels"]:

        lines.append(
            ""
        )

        lines.append(
            "Channels involved:"
        )

        for item in safe["channels"]:

            lines.append(
                f"- {item}"
            )

    if safe["reasons"]:

        lines.append(
            ""
        )

        lines.append(
            "Why ElderShield raised a warning:"
        )

        for item in safe["reasons"]:

            lines.append(
                f"- {item}"
            )

    if safe["dangerous_actions"]:

        lines.append(
            ""
        )

        lines.append(
            "Dangerous actions detected:"
        )

        for item in safe["dangerous_actions"]:

            lines.append(
                f"- {item}"
            )

    if safe["actions"]:

        lines.append(
            ""
        )

        lines.append(
            "Recommended actions:"
        )

        for item in safe["actions"]:

            lines.append(
                f"- {item}"
            )

    lines.append(
        ""
    )

    lines.append(
        "Evidence counts:"
    )

    lines.append(
        f"- Evidence sources: {safe['evidence_count']}"
    )

    lines.append(
        f"- Strong signals: {safe['strong_signal_count']}"
    )

    lines.append(
        f"- Critical signals: {safe['critical_signal_count']}"
    )

    lines.append(
        ""
    )

    lines.append(
        "Privacy:"
    )

    lines.append(
        "- Raw message stored: No"
    )

    lines.append(
        "- Raw audio stored: No"
    )

    lines.append(
        "- Raw image stored: No"
    )

    lines.append(
        "- Credentials stored: No"
    )

    lines.append(
        ""
    )

    lines.append(
        "IMPORTANT:"
    )

    lines.append(
        "This report is a safety aid and is not proof of fraud."
    )

    lines.append(
        "Verify important claims through official channels."
    )

    result = "\n".join(
        lines
    )

    return result[
        :MAX_EXPORT_TEXT
    ]


# ============================================================
# MARKDOWN EXPORT
# ============================================================

def incident_to_markdown(
    incident: dict[str, Any] | None,
) -> str:
    """
    Create a Markdown incident report.
    """

    safe = sanitize_incident(
        incident
    )

    lines = [
        "# ElderShield Safety Incident Report",
        "",
        f"**Incident ID:** `{safe['incident_id']}`",
        "",
        f"**Date:** {safe['created_at']}",
        "",
        f"**Risk:** **{safe['risk']}**",
        "",
    ]

    if safe["headline"]:

        lines.extend(
            [
                "## Headline",
                "",
                safe["headline"],
                "",
            ]
        )

    if safe["summary"]:

        lines.extend(
            [
                "## Summary",
                "",
                safe["summary"],
                "",
            ]
        )

    if safe["categories"]:

        lines.extend(
            [
                "## Possible Scam Categories",
                "",
            ]
        )

        for item in safe["categories"]:

            lines.append(
                f"- {item}"
            )

        lines.append(
            ""
        )

    if safe["reasons"]:

        lines.extend(
            [
                "## Warning Signals",
                "",
            ]
        )

        for item in safe["reasons"]:

            lines.append(
                f"- {item}"
            )

        lines.append(
            ""
        )

    if safe["actions"]:

        lines.extend(
            [
                "## Recommended Actions",
                "",
            ]
        )

        for item in safe["actions"]:

            lines.append(
                f"- {item}"
            )

        lines.append(
            ""
        )

    lines.extend(
        [
            "## Privacy",
            "",
            "- Raw message stored: **No**",
            "- Raw audio stored: **No**",
            "- Raw image stored: **No**",
            "- Credentials stored: **No**",
            "",
            "> ElderShield is a safety aid, not a guarantee.",
        ]
    )

    return "\n".join(
        lines
    )[:MAX_EXPORT_TEXT]


# ============================================================
# EXPORT FILENAME
# ============================================================

def export_filename(
    incident: dict[str, Any] | None,
    extension: str = "txt",
) -> str:
    """
    Generate a safe filename.
    """

    safe = sanitize_incident(
        incident
    )

    incident_id = (
        safe["incident_id"]
        or "incident"
    )

    extension = str(
        extension or "txt"
    ).strip().lower()

    if extension not in {
        "txt",
        "json",
        "md",
    }:

        extension = "txt"

    return (
        f"eldershield_{incident_id.lower()}"
        f".{extension}"
    )


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "sanitize_incident",
    "incident_to_json",
    "incident_to_text",
    "incident_to_markdown",
    "export_filename",
]
