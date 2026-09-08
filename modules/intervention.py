"""
ElderShield Intervention Engine

Converts risk and dangerous actions into simple, practical
safety instructions.

Design principle:

    DETECT → EXPLAIN → INTERVENE

This module does not determine whether something is a scam.
It decides what protective action should be recommended based
on evidence supplied by the case engine.
"""

from __future__ import annotations

from typing import Any


# ============================================================
# RISK LEVELS
# ============================================================

RISK_LEVELS = {
    "SAFE": 0,
    "CAUTION": 1,
    "HIGH RISK": 2,
    "CRITICAL": 3,
    "UNKNOWN": 1,
}


# ============================================================
# DANGEROUS ACTIONS
# ============================================================

CRITICAL_ACTIONS = {
    "otp",
    "upi pin",
    "atm pin",
    "password",
    "bank credentials",
    "card pin",
    "remote access",
    "screen sharing",
    "money transfer",
    "payment",
    "approve payment",
}


HIGH_RISK_ACTIONS = {
    "install application",
    "install app",
    "scan qr",
    "payment request",
    "video call",
    "keep camera on",
    "registration payment",
    "joining fee",
    "security deposit",
    "investment payment",
    "tax payment",
    "processing fee",
}


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_action(
    action: Any,
) -> str:
    """
    Normalize an action for comparison.
    """

    if not isinstance(action, str):
        return ""

    return (
        action
        .strip()
        .lower()
    )


def normalize_risk(
    risk: Any,
) -> str:
    """
    Normalize a risk label.
    """

    if not isinstance(risk, str):
        return "UNKNOWN"

    value = (
        risk
        .strip()
        .upper()
    )

    if value == "HIGH":
        return "HIGH RISK"

    if value == "HIGH_RISK":
        return "HIGH RISK"

    return value


# ============================================================
# RISK ESCALATION
# ============================================================

def escalate_risk_for_actions(
    risk: str,
    dangerous_actions: list[str] | None,
) -> str:
    """
    Escalate risk when highly dangerous actions are detected.

    Critical financial/security actions should never allow a
    case to be presented as SAFE.
    """

    normalized_risk = normalize_risk(
        risk
    )

    actions = {
        normalize_action(action)
        for action in (
            dangerous_actions or []
        )
    }

    if actions & CRITICAL_ACTIONS:

        return "CRITICAL"

    if actions & HIGH_RISK_ACTIONS:

        if normalized_risk == "SAFE":
            return "HIGH RISK"

        if normalized_risk == "CAUTION":
            return "HIGH RISK"

    return normalized_risk


# ============================================================
# IMMEDIATE SAFETY ACTIONS
# ============================================================

def get_immediate_actions(
    risk: str,
    dangerous_actions: list[str] | None = None,
    already_paid: bool = False,
    remote_access_granted: bool = False,
) -> list[str]:
    """
    Generate immediate safety actions.

    The wording is intentionally short and easy to understand.
    """

    final_risk = escalate_risk_for_actions(
        risk,
        dangerous_actions,
    )

    actions: list[str] = []

    normalized_actions = {
        normalize_action(action)
        for action in (
            dangerous_actions or []
        )
    }

    # --------------------------------------------------------
    # Already paid
    # --------------------------------------------------------

    if already_paid:

        actions.extend(
            [
                "Do not send any more money.",
                "Contact your bank or payment provider immediately using a trusted official channel.",
                "Keep transaction details and relevant messages for reporting.",
            ]
        )

    # --------------------------------------------------------
    # Remote access already granted
    # --------------------------------------------------------

    if remote_access_granted:

        actions.extend(
            [
                "Disconnect the device from the internet if you believe someone is remotely controlling it.",
                "Do not enter banking credentials while the device may be compromised.",
                "Contact your bank through a trusted channel if banking information may have been exposed.",
            ]
        )

    # --------------------------------------------------------
    # Critical actions
    # --------------------------------------------------------

    if normalized_actions & CRITICAL_ACTIONS:

        actions.extend(
            [
                "STOP before sharing any OTP, PIN, password or banking information.",
                "Do not approve or make a payment because someone is pressuring you.",
                "End the suspicious call or conversation.",
            ]
        )

    # --------------------------------------------------------
    # Remote-access request
    # --------------------------------------------------------

    if (
        "remote access" in normalized_actions
        or "screen sharing" in normalized_actions
    ):

        actions.extend(
            [
                "Do not give the caller remote control of your device.",
                "Do not share your screen with an unsolicited caller.",
            ]
        )

    # --------------------------------------------------------
    # Application installation
    # --------------------------------------------------------

    if (
        "install application" in normalized_actions
        or "install app" in normalized_actions
    ):

        actions.append(
            "Do not install an application because an unknown caller or message tells you to."
        )

    # --------------------------------------------------------
    # QR/payment
    # --------------------------------------------------------

    if (
        "scan qr" in normalized_actions
        or "payment request" in normalized_actions
        or "approve payment" in normalized_actions
    ):

        actions.extend(
            [
                "Do not scan or approve an unexpected QR or payment request.",
                "Remember that a payment approval can send money from your account.",
            ]
        )

    # --------------------------------------------------------
    # Investment
    # --------------------------------------------------------

    if "investment payment" in normalized_actions:

        actions.extend(
            [
                "Do not transfer money based only on an unsolicited investment offer.",
                "Verify the investment service independently.",
            ]
        )

    # --------------------------------------------------------
    # Generic critical response
    # --------------------------------------------------------

    if final_risk == "CRITICAL" and not actions:

        actions.extend(
            [
                "STOP and do not continue.",
                "Do not share financial or authentication information.",
                "Verify the situation independently.",
            ]
        )

    # --------------------------------------------------------
    # High-risk response
    # --------------------------------------------------------

    elif final_risk == "HIGH RISK" and not actions:

        actions.extend(
            [
                "Do not continue until you verify the request.",
                "Do not make payments or share sensitive information.",
                "Use an independently obtained official contact method.",
            ]
        )

    # --------------------------------------------------------
    # Caution
    # --------------------------------------------------------

    elif final_risk == "CAUTION" and not actions:

        actions.extend(
            [
                "Slow down and verify the request.",
                "Do not act because someone is creating urgency.",
            ]
        )

    # --------------------------------------------------------
    # Safe
    # --------------------------------------------------------

    elif final_risk == "SAFE" and not actions:

        actions.extend(
            [
                "No strong warning signal was detected.",
                "Continue to use normal security precautions.",
            ]
        )

    # --------------------------------------------------------
    # Unknown
    # --------------------------------------------------------

    elif final_risk == "UNKNOWN" and not actions:

        actions.extend(
            [
                "Do not take financial action until you can verify the request.",
                "Ask a trusted person for help if you are unsure.",
            ]
        )

    return deduplicate_actions(
        actions
    )


# ============================================================
# CATEGORY-SPECIFIC ACTIONS
# ============================================================

def get_category_actions(
    category: str | None,
) -> list[str]:
    """
    Return additional guidance for common scam categories.
    """

    if not category:
        return []

    category = (
        category
        .strip()
        .lower()
    )

    category_actions = {

        "bank_kyc": [
            "Open your bank's official app yourself instead of using the supplied link.",
            "Contact the bank using a trusted official channel.",
        ],

        "remote_access": [
            "Do not install remote-access software for an unsolicited caller.",
            "Do not allow another person to control your device.",
        ],

        "digital_arrest": [
            "Do not transfer money to avoid an alleged arrest or legal case.",
            "End the call and independently verify any claimed legal issue.",
            "Tell a trusted family member or person you know.",
        ],

        "courier": [
            "Verify the parcel independently through the courier's official channel.",
            "Do not pay unexpected customs or release charges because of a threatening call.",
        ],

        "job": [
            "Verify the employer independently.",
            "Do not pay an unexpected recruitment or joining fee.",
        ],

        "investment": [
            "Do not trust guaranteed or unusually high returns.",
            "Verify the investment service independently before sending money.",
        ],

        "prize": [
            "Do not pay money to receive an unexpected prize or lottery reward.",
            "Verify the promotion independently.",
        ],

        "payment_qr": [
            "Do not scan an unexpected QR code because someone tells you it will receive money.",
            "Read the payment screen carefully before approving anything.",
        ],
    }

    return category_actions.get(
        category,
        [],
    )


# ============================================================
# DEDUPLICATION
# ============================================================

def deduplicate_actions(
    actions: list[str],
) -> list[str]:
    """
    Remove duplicate action messages while preserving order.
    """

    result = []
    seen = set()

    for action in actions:

        if not isinstance(action, str):
            continue

        cleaned = action.strip()

        if not cleaned:
            continue

        key = cleaned.lower()

        if key in seen:
            continue

        seen.add(key)
        result.append(cleaned)

    return result


# ============================================================
# COMPLETE INTERVENTION
# ============================================================

def get_intervention(
    risk: str,
    dangerous_actions: list[str] | None = None,
    category: str | None = None,
    already_paid: bool = False,
    remote_access_granted: bool = False,
) -> dict:
    """
    Generate the complete ElderShield intervention.

    Returns:

        {
            "risk": ...,
            "headline": ...,
            "summary": ...,
            "actions": [...],
            "priority": ...
        }
    """

    final_risk = escalate_risk_for_actions(
        risk,
        dangerous_actions,
    )

    category_actions = get_category_actions(
        category
    )

    immediate_actions = get_immediate_actions(
        final_risk,
        dangerous_actions,
        already_paid,
        remote_access_granted,
    )

    actions = deduplicate_actions(
        immediate_actions
        + category_actions
    )

    # --------------------------------------------------------
    # Headlines
    # --------------------------------------------------------

    if final_risk == "CRITICAL":

        headline = "🛑 STOP — DO NOT CONTINUE"

        summary = (
            "ElderShield detected a high-impact warning sign. "
            "Do not share secrets, approve payments or follow "
            "the caller's instructions."
        )

        priority = "IMMEDIATE"

    elif final_risk == "HIGH RISK":

        headline = "⚠️ HIGH RISK — BE VERY CAREFUL"

        summary = (
            "The request contains significant warning signs. "
            "Do not continue until you independently verify it."
        )

        priority = "HIGH"

    elif final_risk == "CAUTION":

        headline = "🟡 CAUTION — CHECK BEFORE ACTING"

        summary = (
            "Some warning signs were detected. Slow down "
            "and verify the request before taking action."
        )

        priority = "MEDIUM"

    elif final_risk == "SAFE":

        headline = "🟢 NO STRONG WARNING DETECTED"

        summary = (
            "ElderShield did not detect strong scam indicators "
            "in the available evidence."
        )

        priority = "LOW"

    else:

        headline = "⚪ UNABLE TO CONFIRM SAFETY"

        summary = (
            "ElderShield could not confidently assess the "
            "situation. Do not take financial action until "
            "you verify it independently."
        )

        priority = "MEDIUM"

    return {
        "risk": final_risk,
        "headline": headline,
        "summary": summary,
        "actions": actions,
        "priority": priority,
    }
