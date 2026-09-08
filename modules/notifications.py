"""
ElderShield Notification Helpers

Creates concise safety notifications from ElderShield results.

Current web app:
- Displays notifications in the UI.
- Does not send SMS.
- Does not send WhatsApp messages.
- Does not make phone calls.
- Does not contact banks or authorities.

Future native applications may use this module's structured
messages as the basis for device notifications.
"""

from __future__ import annotations

from typing import Any


# ============================================================
# RISK CONFIGURATION
# ============================================================

RISK_PRIORITY = {
    "SAFE": 0,
    "UNKNOWN": 0,
    "CAUTION": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}


RISK_TITLES = {
    "SAFE": "No major warning detected",
    "UNKNOWN": "Unable to determine safety",
    "CAUTION": "Use caution",
    "HIGH": "High-risk warning",
    "CRITICAL": "STOP — critical warning",
}


RISK_EMOJI = {
    "SAFE": "🟢",
    "UNKNOWN": "⚪",
    "CAUTION": "🟡",
    "HIGH": "🟠",
    "CRITICAL": "🔴",
}


# ============================================================
# HELPERS
# ============================================================

def normalize_risk(
    value: Any,
) -> str:
    """
    Normalize an ElderShield risk value.
    """

    risk = str(
        value or "UNKNOWN"
    ).strip().upper()

    if risk not in RISK_PRIORITY:

        return "UNKNOWN"

    return risk


def _first_reason(
    case: dict[str, Any],
) -> str:
    """
    Return the first useful reason from a case.
    """

    reasons = case.get(
        "reasons",
        [],
    )

    if isinstance(
        reasons,
        list,
    ):

        for reason in reasons:

            value = str(
                reason or ""
            ).strip()

            if value:

                return value

    return ""


def _first_action(
    case: dict[str, Any],
) -> str:
    """
    Return the first recommended action.
    """

    actions = case.get(
        "actions",
        case.get(
            "recommended_actions",
            [],
        ),
    )

    if isinstance(
        actions,
        list,
    ):

        for action in actions:

            value = str(
                action or ""
            ).strip()

            if value:

                return value

    return ""


# ============================================================
# NOTIFICATION CREATION
# ============================================================

def create_notification(
    case_result: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Create a concise notification from an analysis result.

    Raw evidence is never included automatically.
    """

    if not isinstance(
        case_result,
        dict,
    ):

        case_result = {}

    risk = normalize_risk(
        case_result.get(
            "risk",
            "UNKNOWN",
        )
    )

    headline = str(
        case_result.get(
            "headline",
            "",
        )
        or ""
    ).strip()

    reason = _first_reason(
        case_result
    )

    action = _first_action(
        case_result
    )

    title = RISK_TITLES[
        risk
    ]

    emoji = RISK_EMOJI[
        risk
    ]

    # --------------------------------------------------------
    # Main message
    # --------------------------------------------------------

    if risk == "CRITICAL":

        message = (
            "Stop the requested action. "
            "Do not share OTPs, PINs, passwords or banking credentials."
        )

    elif risk == "HIGH":

        message = (
            "Do not pay, install software or share sensitive information "
            "until the claim has been independently verified."
        )

    elif risk == "CAUTION":

        message = (
            "Pause and verify the request through an official channel "
            "before taking action."
        )

    elif risk == "SAFE":

        message = (
            "No major scam warning was detected from the available evidence."
        )

    else:

        message = (
            "ElderShield could not confidently determine whether this is safe."
        )

    return {
        "risk": risk,
        "priority": RISK_PRIORITY[
            risk
        ],
        "title": f"{emoji} {title}",
        "headline": headline[:300],
        "message": message,
        "reason": reason[:500],
        "action": action[:500],
        "requires_attention": risk in {
            "CAUTION",
            "HIGH",
            "CRITICAL",
        },
        "raw_evidence_included": False,
    }


# ============================================================
# SHORT NOTIFICATION
# ============================================================

def notification_text(
    case_result: dict[str, Any] | None,
) -> str:
    """
    Return a short notification suitable for a banner.
    """

    notification = create_notification(
        case_result
    )

    return (
        f"{notification['title']}: "
        f"{notification['message']}"
    )


# ============================================================
# CRITICAL ALERT
# ============================================================

def critical_alert(
    case_result: dict[str, Any] | None,
) -> str:
    """
    Return a concise critical safety alert.
    """

    risk = normalize_risk(
        (
            case_result or {}
        ).get(
            "risk",
            "UNKNOWN",
        )
    )

    if risk != "CRITICAL":

        return ""

    return (
        "🔴 STOP. Do not share OTPs, UPI PINs, ATM PINs, "
        "passwords or card credentials. Do not transfer money "
        "or give remote access. Verify independently."
    )


# ============================================================
# CALL ALERT
# ============================================================

def call_notification(
    risk: Any,
) -> dict[str, Any]:
    """
    Create a compact notification specifically for the
    Incoming Call Guard.
    """

    normalized = normalize_risk(
        risk
    )

    if normalized == "CRITICAL":

        return {
            "risk": normalized,
            "title": "🔴 DO NOT PROCEED",
            "message": (
                "The call contains a critical safety signal. "
                "Do not share credentials, transfer money or "
                "give remote access."
            ),
        }

    if normalized == "HIGH":

        return {
            "risk": normalized,
            "title": "🟠 HIGH RISK CALL",
            "message": (
                "Pause. Verify the caller independently before "
                "taking any action."
            ),
        }

    if normalized == "CAUTION":

        return {
            "risk": normalized,
            "title": "🟡 USE CAUTION",
            "message": (
                "Do not rush. Never share OTPs, PINs or passwords."
            ),
        }

    if normalized == "SAFE":

        return {
            "risk": normalized,
            "title": "🟢 NO MAJOR WARNING",
            "message": (
                "No major warning was detected from the available information."
            ),
        }

    return {
        "risk": "UNKNOWN",
        "title": "⚪ UNKNOWN",
        "message": (
            "There is not enough information to determine whether "
            "the caller is safe."
        ),
    }


# ============================================================
# STREAMLIT DISPLAY
# ============================================================

def display_notification(
    case_result: dict[str, Any] | None,
) -> None:
    """
    Display an analysis notification in Streamlit.

    Imported lazily so this module remains testable outside Streamlit.
    """

    notification = create_notification(
        case_result
    )

    try:

        import streamlit as st

    except Exception:

        return

    risk = notification[
        "risk"
    ]

    if risk == "CRITICAL":

        st.error(
            f"{notification['title']}\n\n"
            f"{notification['message']}"
        )

    elif risk == "HIGH":

        st.warning(
            f"{notification['title']}\n\n"
            f"{notification['message']}"
        )

    elif risk == "CAUTION":

        st.warning(
            f"{notification['title']}\n\n"
            f"{notification['message']}"
        )

    elif risk == "SAFE":

        st.success(
            f"{notification['title']}\n\n"
            f"{notification['message']}"
        )

    else:

        st.info(
            f"{notification['title']}\n\n"
            f"{notification['message']}"
        )


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "RISK_PRIORITY",
    "RISK_TITLES",
    "RISK_EMOJI",
    "normalize_risk",
    "create_notification",
    "notification_text",
    "critical_alert",
    "call_notification",
    "display_notification",
]
