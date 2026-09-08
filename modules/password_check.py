"""
ElderShield Credential Safety Checks

Detects suspicious requests involving:
- Passwords
- Login credentials
- Banking credentials
- OTPs
- PINs
- CVV/CVC
- Security codes

IMPORTANT:
This module must never receive or store a user's actual password,
OTP, PIN or banking credential.

It analyzes surrounding text only.
"""

from __future__ import annotations

import re
from typing import Any


# ============================================================
# CONSTANTS
# ============================================================

MAX_TEXT_LENGTH = 20_000


# Requests for credentials.
CREDENTIAL_REQUEST_PATTERNS = (
    r"\b(?:share|send|tell|give|provide|enter|submit)"
    r"\b.{0,60}\b(?:password|passcode|login\s+details|"
    r"login\s+credentials|user\s*id|username)\b",

    r"\b(?:password|passcode|login\s+details|"
    r"login\s+credentials)\b.{0,60}"
    r"\b(?:share|send|tell|give|provide|enter|submit)\b",

    r"\b(?:share|send|tell|give|provide|enter|submit)"
    r"\b.{0,60}\b(?:otp|one[\s-]?time[\s-]?password)\b",

    r"\b(?:share|send|tell|give|provide|enter|submit)"
    r"\b.{0,60}\b(?:upi[\s-]?pin|atm[\s-]?pin|cvv|cvc)\b",
)


# Pressure associated with credential theft.
CREDENTIAL_PRESSURE_PATTERNS = (
    r"\b(?:account|card|bank|wallet)\b.{0,60}"
    r"\b(?:blocked|suspended|locked|deactivated)\b",

    r"\b(?:verify|confirm|validate|update)\b.{0,60}"
    r"\b(?:account|kyc|identity|bank|card)\b",

    r"\b(?:urgent|immediately|right\s+now|within\s+\d+"
    r"\s*(?:minutes?|hours?))\b",

    r"\b(?:otherwise|else)\b.{0,60}"
    r"\b(?:blocked|suspended|arrested|penalty|fine|cancelled)\b",
)


# Suspicious login instructions.
LOGIN_RISK_PATTERNS = (
    r"\bclick\b.{0,80}\b(?:login|sign\s*in|verify|secure)\b",

    r"\blogin\b.{0,80}\b(?:link|url|website|page)\b",

    r"\b(?:download|install)\b.{0,80}"
    r"\b(?:security|verification|banking|support)\b",
)


# ============================================================
# HELPERS
# ============================================================

def _find_matches(
    text: str,
    patterns: tuple[str, ...],
) -> list[str]:
    """
    Return matched pattern descriptions without returning
    sensitive values.
    """

    matches: list[str] = []

    for pattern in patterns:

        try:

            if re.search(
                pattern,
                text,
                flags=re.IGNORECASE,
            ):

                matches.append(
                    pattern
                )

        except re.error:

            continue

    return matches


def _contains_sensitive_value(
    text: str,
) -> bool:
    """
    Detect obvious credential-like values.

    The values themselves are never returned.
    """

    patterns = (
        # Six-digit OTP-like number.
        r"\b\d{6}\b",

        # Four to six digit PIN-like number following a label.
        r"(?i)\b(?:otp|pin|upi[\s-]?pin|atm[\s-]?pin)"
        r"\s*(?:is|:|=)\s*\d{4,8}\b",

        # CVV/CVC.
        r"(?i)\b(?:cvv|cvc)"
        r"\s*(?:is|:|=)\s*\d{3,4}\b",
    )

    return any(
        re.search(
            pattern,
            text,
        )
        for pattern in patterns
    )


# ============================================================
# ANALYSIS
# ============================================================

def analyze_credential_request(
    text: Any,
) -> dict[str, Any]:
    """
    Analyze text for credential-theft indicators.

    Actual passwords/PINs/OTPs should never be intentionally
    supplied to this function.
    """

    value = str(
        text or ""
    ).strip()

    if len(value) > MAX_TEXT_LENGTH:

        value = value[
            :MAX_TEXT_LENGTH
        ]

    if not value:

        return {
            "risk": "UNKNOWN",
            "credential_request": False,
            "credential_types": [],
            "signal_groups": [],
            "reasons": [],
            "recommended_actions": [
                "Never share passwords, OTPs or PINs with callers or messages."
            ],
        }

    lowered = value.lower()

    request_matches = _find_matches(
        value,
        CREDENTIAL_REQUEST_PATTERNS,
    )

    pressure_matches = _find_matches(
        value,
        CREDENTIAL_PRESSURE_PATTERNS,
    )

    login_matches = _find_matches(
        value,
        LOGIN_RISK_PATTERNS,
    )

    credential_types: list[str] = []

    if re.search(
        r"\bpassword\b|\bpasscode\b|\blogin\s+credentials?\b",
        lowered,
    ):

        credential_types.append(
            "PASSWORD"
        )

    if re.search(
        r"\botp\b|one[\s-]?time[\s-]?password",
        lowered,
    ):

        credential_types.append(
            "OTP"
        )

    if re.search(
        r"\bupi[\s-]?pin\b",
        lowered,
    ):

        credential_types.append(
            "UPI PIN"
        )

    if re.search(
        r"\batm[\s-]?pin\b",
        lowered,
    ):

        credential_types.append(
            "ATM PIN"
        )

    if re.search(
        r"\bcvv\b|\bcvc\b",
        lowered,
    ):

        credential_types.append(
            "CVV/CVC"
        )

    if re.search(
        r"\b(?:user\s*id|username)\b",
        lowered,
    ):

        credential_types.append(
            "USERNAME"
        )

    # Remove duplicates while preserving order.
    credential_types = list(
        dict.fromkeys(
            credential_types
        )
    )

    reasons: list[str] = []
    signal_groups: list[str] = []

    if request_matches:

        reasons.append(
            "The text appears to request sensitive login or "
            "authentication information."
        )

        signal_groups.append(
            "credential_request"
        )

    if pressure_matches:

        reasons.append(
            "The request uses pressure, urgency or account-related "
            "consequences."
        )

        signal_groups.append(
            "credential_pressure"
        )

    if login_matches:

        reasons.append(
            "The text contains instructions associated with "
            "potentially unsafe login or verification flows."
        )

        signal_groups.append(
            "suspicious_login"
        )

    contains_value = _contains_sensitive_value(
        value
    )

    if contains_value:

        reasons.append(
            "The text appears to contain a credential-like value. "
            "Do not share such values with ElderShield or anyone else."
        )

        signal_groups.append(
            "possible_sensitive_value"
        )

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    if request_matches:

        risk = "CRITICAL"

    elif (
        pressure_matches
        and credential_types
    ):

        risk = "HIGH"

    elif login_matches:

        risk = "CAUTION"

    elif credential_types:

        risk = "CAUTION"

    else:

        risk = "UNKNOWN"

    # --------------------------------------------------------
    # Actions
    # --------------------------------------------------------

    recommended_actions = [
        "Never share your password with a caller or message sender.",
        "Never share OTPs, UPI PINs, ATM PINs or CVV/CVC codes.",
        "Open the official app or website yourself instead of using a supplied login link.",
    ]

    if request_matches:

        recommended_actions.insert(
            0,
            "Stop and do not provide the requested credential.",
        )

    if contains_value:

        recommended_actions.insert(
            0,
            "Do not send credentials to ElderShield. If you already shared one, secure the account through its official channel.",
        )

    return {
        "risk": risk,
        "credential_request": bool(
            request_matches
        ),
        "credential_types": credential_types,
        "signal_groups": list(
            dict.fromkeys(
                signal_groups
            )
        ),
        "reasons": reasons,
        "recommended_actions": list(
            dict.fromkeys(
                recommended_actions
            )
        ),
        "disclaimer": (
            "Credential analysis identifies suspicious requests; "
            "it does not inspect or verify the actual credentials."
        ),
    }


# ============================================================
# SAFE CREDENTIAL REMINDER
# ============================================================

def credential_safety_reminder() -> str:
    """
    Return the standard ElderShield credential safety reminder.
    """

    return (
        "ElderShield will never need your OTP, UPI PIN, ATM PIN, "
        "CVV, password or full banking credentials."
    )


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "MAX_TEXT_LENGTH",
    "analyze_credential_request",
    "credential_safety_reminder",
]
