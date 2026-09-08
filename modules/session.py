"""
ElderShield Session Management

Manages temporary Streamlit-session state such as:
- Analysis history
- Current case
- Privacy acknowledgement
- Selected language

IMPORTANT:
- This is temporary session state, not permanent storage.
- Do not store passwords, OTPs, PINs or other secrets.
- History entries should contain summarized safety results,
  not raw sensitive user content.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


# ============================================================
# CONSTANTS
# ============================================================

HISTORY_KEY = "eldershield_history"
CURRENT_CASE_KEY = "eldershield_current_case"
PRIVACY_KEY = "eldershield_privacy_acknowledged"
LANGUAGE_KEY = "eldershield_language"

MAX_HISTORY_ITEMS = 20


# ============================================================
# STREAMLIT ACCESS
# ============================================================

def get_session_state():
    """
    Safely access Streamlit session state.

    Streamlit is imported lazily so the module can also be
    imported during tests without requiring an active app.
    """

    try:

        import streamlit as st

        return st.session_state

    except Exception as exc:

        raise RuntimeError(
            "Streamlit session state is unavailable."
        ) from exc


# ============================================================
# INITIALIZATION
# ============================================================

def initialize_session() -> None:
    """
    Initialize ElderShield session values.
    """

    state = get_session_state()

    if HISTORY_KEY not in state:

        state[HISTORY_KEY] = []

    if CURRENT_CASE_KEY not in state:

        state[CURRENT_CASE_KEY] = None

    if PRIVACY_KEY not in state:

        state[PRIVACY_KEY] = False

    if LANGUAGE_KEY not in state:

        state[LANGUAGE_KEY] = "en"


# ============================================================
# PRIVACY
# ============================================================

def set_privacy_acknowledged(
    acknowledged: bool,
) -> None:
    """
    Store the user's privacy acknowledgement.
    """

    state = get_session_state()

    state[PRIVACY_KEY] = bool(
        acknowledged
    )


def is_privacy_acknowledged() -> bool:
    """
    Return whether the user acknowledged the safety/privacy notice.
    """

    state = get_session_state()

    return bool(
        state.get(
            PRIVACY_KEY,
            False,
        )
    )


# ============================================================
# LANGUAGE
# ============================================================

def set_language(
    language: str,
) -> None:
    """
    Set the current UI language.
    """

    state = get_session_state()

    value = str(
        language or "en"
    ).strip().lower()

    if not value:

        value = "en"

    state[LANGUAGE_KEY] = value


def get_language() -> str:
    """
    Get current UI language.
    """

    state = get_session_state()

    return str(
        state.get(
            LANGUAGE_KEY,
            "en",
        )
    )


# ============================================================
# CURRENT CASE
# ============================================================

def set_current_case(
    case: dict[str, Any] | None,
) -> None:
    """
    Store the current case result.

    Only the structured result should be stored.
    """

    state = get_session_state()

    if case is None:

        state[CURRENT_CASE_KEY] = None

        return

    if not isinstance(
        case,
        dict,
    ):

        raise TypeError(
            "Current case must be a dictionary."
        )

    state[CURRENT_CASE_KEY] = dict(
        case
    )


def get_current_case() -> dict[str, Any] | None:
    """
    Return current case result.
    """

    state = get_session_state()

    value = state.get(
        CURRENT_CASE_KEY
    )

    if isinstance(
        value,
        dict,
    ):

        return value

    return None


def clear_current_case() -> None:
    """
    Remove current case.
    """

    state = get_session_state()

    state[CURRENT_CASE_KEY] = None


# ============================================================
# HISTORY
# ============================================================

def _safe_history_entry(
    case: dict[str, Any],
) -> dict[str, Any]:
    """
    Convert a case into a privacy-conscious history entry.

    Raw messages, transcripts and image/audio bytes are NOT stored.
    """

    risk = str(
        case.get(
            "risk",
            "UNKNOWN",
        )
    )

    summary = str(
        case.get(
            "summary",
            "",
        )
    ).strip()

    headline = str(
        case.get(
            "headline",
            "",
        )
    ).strip()

    categories = case.get(
        "categories",
        [],
    )

    if not isinstance(
        categories,
        list,
    ):

        categories = []

    categories = [
        str(category)
        for category in categories
        if str(category).strip()
    ][:10]

    channels = case.get(
        "channels",
        [],
    )

    if not isinstance(
        channels,
        list,
    ):

        channels = []

    channels = [
        str(channel)
        for channel in channels
        if str(channel).strip()
    ][:10]

    return {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "risk": risk,

        "headline": headline,

        "summary": summary[:500],

        "categories": categories,

        "channels": channels,
    }


def add_history(
    case: dict[str, Any],
) -> None:
    """
    Add a privacy-conscious case summary to session history.
    """

    if not isinstance(
        case,
        dict,
    ):

        return

    state = get_session_state()

    if HISTORY_KEY not in state:

        state[HISTORY_KEY] = []

    entry = _safe_history_entry(
        case
    )

    history = state[
        HISTORY_KEY
    ]

    if not isinstance(
        history,
        list,
    ):

        history = []

    history.insert(
        0,
        entry,
    )

    state[HISTORY_KEY] = history[
        :MAX_HISTORY_ITEMS
    ]


def get_history() -> list[dict[str, Any]]:
    """
    Return session history.
    """

    state = get_session_state()

    history = state.get(
        HISTORY_KEY,
        [],
    )

    if not isinstance(
        history,
        list,
    ):

        return []

    return list(
        history
    )


def clear_history() -> None:
    """
    Delete all session history.
    """

    state = get_session_state()

    state[HISTORY_KEY] = []


# ============================================================
# SESSION SNAPSHOT
# ============================================================

def get_session_snapshot() -> dict[str, Any]:
    """
    Return a safe diagnostic snapshot.

    No raw user content is included.
    """

    return {
        "language": get_language(),
        "privacy_acknowledged": is_privacy_acknowledged(),
        "history_count": len(
            get_history()
        ),
        "has_current_case": (
            get_current_case()
            is not None
        ),
    }
