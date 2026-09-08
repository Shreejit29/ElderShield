"""
ElderShield User Feedback

Handles privacy-conscious feedback about an analysis result.

Supported feedback:
- Helpful
- Not helpful
- Unsure

Only structured feedback is stored in the current session.
Raw user evidence is never included automatically.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


# ============================================================
# CONSTANTS
# ============================================================

FEEDBACK_KEY = "eldershield_feedback"

MAX_FEEDBACK_ITEMS = 50

ALLOWED_FEEDBACK = {
    "HELPFUL",
    "NOT_HELPFUL",
    "UNSURE",
}


# ============================================================
# STREAMLIT SESSION
# ============================================================

def _session_state():
    """
    Safely access Streamlit session state.
    """

    try:

        import streamlit as st

        return st.session_state

    except Exception as exc:

        raise RuntimeError(
            "Streamlit session state is unavailable."
        ) from exc


def initialize_feedback() -> None:
    """
    Initialize feedback storage.
    """

    state = _session_state()

    if FEEDBACK_KEY not in state:

        state[FEEDBACK_KEY] = []


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_feedback(
    feedback: Any,
) -> str:
    """
    Normalize a feedback value.
    """

    value = str(
        feedback or ""
    ).strip().upper()

    if value not in ALLOWED_FEEDBACK:

        return "UNSURE"

    return value


# ============================================================
# FEEDBACK ID
# ============================================================

def generate_feedback_id() -> str:
    """
    Generate a non-sensitive feedback identifier.
    """

    return (
        "FB-"
        + uuid4().hex[:10].upper()
    )


# ============================================================
# ADD FEEDBACK
# ============================================================

def add_feedback(
    feedback: Any,
    *,
    incident_id: str = "",
    risk: str = "UNKNOWN",
    channel: str = "",
) -> dict[str, Any]:
    """
    Add a privacy-conscious feedback record.

    No raw user evidence is accepted or stored here.
    """

    state = _session_state()

    if FEEDBACK_KEY not in state:

        state[FEEDBACK_KEY] = []

    normalized_feedback = normalize_feedback(
        feedback
    )

    record = {
        "feedback_id": generate_feedback_id(),

        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "feedback": normalized_feedback,

        "incident_id": str(
            incident_id or ""
        ).strip()[:100],

        "risk": str(
            risk or "UNKNOWN"
        ).strip().upper()[:30],

        "channel": str(
            channel or ""
        ).strip()[:50],

        "raw_evidence_stored": False,
    }

    history = state[
        FEEDBACK_KEY
    ]

    if not isinstance(
        history,
        list,
    ):

        history = []

    history.insert(
        0,
        record,
    )

    state[
        FEEDBACK_KEY
    ] = history[
        :MAX_FEEDBACK_ITEMS
    ]

    return dict(
        record
    )


# ============================================================
# READ FEEDBACK
# ============================================================

def get_feedback() -> list[dict[str, Any]]:
    """
    Return feedback collected during this session.
    """

    state = _session_state()

    value = state.get(
        FEEDBACK_KEY,
        [],
    )

    if not isinstance(
        value,
        list,
    ):

        return []

    return list(
        value
    )


def clear_feedback() -> None:
    """
    Delete feedback from the current session.
    """

    state = _session_state()

    state[
        FEEDBACK_KEY
    ] = []


# ============================================================
# FEEDBACK SUMMARY
# ============================================================

def feedback_summary() -> dict[str, int]:
    """
    Return aggregate feedback counts.
    """

    records = get_feedback()

    summary = {
        "HELPFUL": 0,
        "NOT_HELPFUL": 0,
        "UNSURE": 0,
    }

    for record in records:

        if not isinstance(
            record,
            dict,
        ):

            continue

        value = normalize_feedback(
            record.get(
                "feedback",
                "UNSURE",
            )
        )

        summary[
            value
        ] += 1

    return summary


# ============================================================
# FEEDBACK MESSAGE
# ============================================================

def feedback_prompt() -> str:
    """
    Return the standard user-facing feedback prompt.
    """

    return (
        "Was this ElderShield warning helpful? "
        "Your feedback helps improve the safety system."
    )


def feedback_privacy_note() -> str:
    """
    Return a privacy explanation for the feedback UI.
    """

    return (
        "Feedback records contain only a small safety summary. "
        "Your original message, screenshot, audio and credentials "
        "are not added automatically."
    )


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "FEEDBACK_KEY",
    "MAX_FEEDBACK_ITEMS",
    "ALLOWED_FEEDBACK",
    "normalize_feedback",
    "generate_feedback_id",
    "add_feedback",
    "get_feedback",
    "clear_feedback",
    "feedback_summary",
    "feedback_prompt",
    "feedback_privacy_note",
]
