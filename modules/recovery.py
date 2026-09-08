"""
ElderShield Recovery & Damage-Control Guidance

Provides immediate safety guidance after a potentially harmful
action has already occurred.

IMPORTANT:
- This module does not recover money.
- It does not contact banks or police.
- It does not guarantee recovery.
- It never asks for OTPs, PINs, passwords or full card credentials.
- It warns against secondary "recovery scams".
"""

from __future__ import annotations

from typing import Any


# ============================================================
# CONSTANTS
# ============================================================

RECOVERY_SCAM_TERMS = (
    "recovery agent",
    "recover money",
    "money recovery",
    "refund agent",
    "cyber recovery",
    "guaranteed recovery",
    "pay recovery fee",
    "recovery fee",
    "processing fee",
    "legal fee",
)


# ============================================================
# BASIC HELPERS
# ============================================================

def _normalize(
    value: Any,
) -> str:
    """
    Normalize text for keyword matching.
    """

    return str(
        value or ""
    ).strip().lower()


def _has_any(
    text: str,
    terms: tuple[str, ...],
) -> bool:
    """
    Return True when any supplied term occurs.
    """

    return any(
        term in text
        for term in terms
    )


# ============================================================
# RECOVERY-SCAM DETECTION
# ============================================================

def detect_recovery_scam(
    text: Any,
) -> dict[str, Any]:
    """
    Detect language associated with secondary recovery scams.
    """

    value = _normalize(
        text
    )

    matches = [
        term
        for term in RECOVERY_SCAM_TERMS
        if term in value
    ]

    if matches:

        return {
            "detected": True,
            "risk": "HIGH",
            "matches": matches,
            "reasons": [
                "The content contains language associated with "
                "possible recovery or refund scams."
            ],
            "actions": [
                "Do not pay anyone who promises guaranteed recovery.",
                "Do not share OTPs, PINs, passwords or banking credentials.",
                "Use your bank/payment provider's official fraud-reporting channel.",
                "Do not trust unofficial agents claiming they can recover funds for an upfront fee.",
            ],
        }

    return {
        "detected": False,
        "risk": "UNKNOWN",
        "matches": [],
        "reasons": [],
        "actions": [],
    }


# ============================================================
# DAMAGE CONTROL
# ============================================================

def get_damage_control(
    *,
    money_sent: bool = False,
    otp_shared: bool = False,
    pin_shared: bool = False,
    password_shared: bool = False,
    card_details_shared: bool = False,
    remote_access_granted: bool = False,
    suspicious_app_installed: bool = False,
    digital_arrest: bool = False,
) -> dict[str, Any]:
    """
    Return immediate damage-control steps.

    These are general safety steps. Users should contact the
    relevant official institution as quickly as possible.
    """

    actions: list[str] = []
    priority: list[str] = []

    # --------------------------------------------------------
    # Money already sent
    # --------------------------------------------------------

    if money_sent:

        priority.append(
            "Contact your bank or payment provider immediately "
            "through its official fraud-reporting channel."
        )

        actions.extend(
            [
                "Report the transaction as fraudulent as soon as possible.",
                "Save the transaction/reference number.",
                "Keep screenshots and other evidence of the scam.",
                "Do not send additional money to 'unlock' or recover the transfer.",
            ]
        )

    # --------------------------------------------------------
    # OTP
    # --------------------------------------------------------

    if otp_shared:

        priority.append(
            "If an OTP was shared, contact the affected bank/service "
            "through its official channel immediately."
        )

        actions.extend(
            [
                "Ask the provider whether the account or transaction can be secured.",
                "Review recent account activity for unauthorized transactions.",
                "Do not share any further OTPs.",
            ]
        )

    # --------------------------------------------------------
    # PIN
    # --------------------------------------------------------

    if pin_shared:

        priority.append(
            "If a UPI PIN or ATM/card PIN was shared, secure the "
            "affected account immediately using official channels."
        )

        actions.extend(
            [
                "Change the affected PIN using the official banking/payment application or approved method.",
                "Check recent transactions.",
                "Do not disclose the new PIN to anyone.",
            ]
        )

    # --------------------------------------------------------
    # Password
    # --------------------------------------------------------

    if password_shared:

        priority.append(
            "Change the affected password immediately using the "
            "official website or app."
        )

        actions.extend(
            [
                "Sign out other sessions if the service provides that option.",
                "Enable stronger authentication where available.",
                "Do not reuse the compromised password elsewhere.",
            ]
        )

    # --------------------------------------------------------
    # Card details
    # --------------------------------------------------------

    if card_details_shared:

        priority.append(
            "Contact the card issuer through its official channel "
            "and ask whether the card should be blocked or replaced."
        )

        actions.extend(
            [
                "Monitor recent card transactions.",
                "Report unauthorized transactions immediately.",
                "Do not share additional card information with callers.",
            ]
        )

    # --------------------------------------------------------
    # Remote access
    # --------------------------------------------------------

    if remote_access_granted:

        priority.append(
            "Disconnect the device from the internet if the scammer "
            "still appears to have remote access."
        )

        actions.extend(
            [
                "End the remote-access session.",
                "Uninstall unauthorized remote-access software if safe to do so.",
                "Change important passwords from a trusted device.",
                "Check banking and email accounts for unauthorized activity.",
                "Consider professional device-security assistance if you are unsure what was changed.",
            ]
        )

    # --------------------------------------------------------
    # Suspicious application
    # --------------------------------------------------------

    if suspicious_app_installed:

        priority.append(
            "Do not open or use the suspicious application again."
        )

        actions.extend(
            [
                "Disconnect the device from the internet if the app may have remote-control capabilities.",
                "Remove the suspicious application if you can do so safely.",
                "Review app permissions.",
                "Change important credentials from a trusted device.",
            ]
        )

    # --------------------------------------------------------
    # Digital arrest
    # --------------------------------------------------------

    if digital_arrest:

        priority.append(
            "End the call and do not make payments because of threats "
            "of arrest or legal action over a video/phone call."
        )

        actions.extend(
            [
                "Do not transfer money to prove your innocence.",
                "Do not share OTPs, PINs or passwords.",
                "Verify any legal claim independently using official channels.",
                "Preserve the caller's messages, numbers and evidence.",
            ]
        )

    # --------------------------------------------------------
    # Generic fallback
    # --------------------------------------------------------

    if not (
        money_sent
        or otp_shared
        or pin_shared
        or password_shared
        or card_details_shared
        or remote_access_granted
        or suspicious_app_installed
        or digital_arrest
    ):

        actions.extend(
            [
                "Stop communicating with the suspected scammer.",
                "Do not make any further payment.",
                "Preserve screenshots, messages, phone numbers and transaction details.",
                "Contact the relevant organization through its official channel.",
            ]
        )

    # --------------------------------------------------------
    # Recovery scam warning
    # --------------------------------------------------------

    actions.append(
        "Be alert for follow-up recovery scams. Genuine authorities "
        "or banks should not require an unofficial upfront fee to recover money."
    )

    # Remove duplicates.
    priority = list(
        dict.fromkeys(
            priority
        )
    )

    actions = list(
        dict.fromkeys(
            actions
        )
    )

    return {
        "priority": priority,
        "actions": actions,
        "risk": (
            "CRITICAL"
            if (
                money_sent
                or otp_shared
                or pin_shared
                or password_shared
                or card_details_shared
                or remote_access_granted
            )
            else "HIGH"
            if (
                suspicious_app_installed
                or digital_arrest
            )
            else "CAUTION"
        ),
    }


# ============================================================
# CASE-RESULT INTEGRATION
# ============================================================

def recovery_guidance_from_case(
    case_result: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Derive conservative recovery guidance from a case result.

    This function uses explicit dangerous-action indicators when
    available. It does not infer that a user definitely suffered
    a loss.
    """

    if not isinstance(
        case_result,
        dict,
    ):

        return get_damage_control()

    dangerous = case_result.get(
        "dangerous_actions",
        [],
    )

    if not isinstance(
        dangerous,
        list,
    ):

        dangerous = []

    normalized = {
        str(item).upper()
        for item in dangerous
    }

    return get_damage_control(
        money_sent=(
            "MONEY TRANSFER" in normalized
            or "PAYMENT" in normalized
        ),
        otp_shared=(
            "OTP" in normalized
        ),
        pin_shared=(
            "UPI PIN" in normalized
            or "ATM PIN" in normalized
            or "CARD PIN" in normalized
        ),
        password_shared=(
            "PASSWORD" in normalized
            or "BANK CREDENTIALS" in normalized
        ),
        card_details_shared=(
            "CARD DETAILS" in normalized
            or "CVV" in normalized
        ),
        remote_access_granted=(
            "REMOTE ACCESS" in normalized
            or "SCREEN SHARING" in normalized
        ),
        suspicious_app_installed=(
            "INSTALL APP" in normalized
        ),
        digital_arrest=(
            "DIGITAL ARREST" in normalized
        ),
    )


# ============================================================
# RECOVERY SAFETY REMINDER
# ============================================================

def recovery_safety_reminder() -> str:
    """
    Return the standard recovery-scam warning.
    """

    return (
        "If someone contacts you later claiming they can recover "
        "your money for a fee, treat the request as suspicious and "
        "verify it independently."
    )


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "RECOVERY_SCAM_TERMS",
    "detect_recovery_scam",
    "get_damage_control",
    "recovery_guidance_from_case",
    "recovery_safety_reminder",
]
