"""
ElderShield Phone Number Safety Checks

Provides conservative, offline checks for suspicious phone numbers.

Important:
- A phone number alone does NOT prove a scam.
- No reverse lookup is performed here.
- No personal identity information is retrieved.
- No phone number is sent to an external service.
- Caller ID can be spoofed.
"""

from __future__ import annotations

import re
from typing import Any


# ============================================================
# CONSTANTS
# ============================================================

INDIA_COUNTRY_CODE = "91"

CRITICAL_TERMS = (
    "otp",
    "upi pin",
    "upi-pin",
    "atm pin",
    "atm-pin",
    "cvv",
    "password",
    "remote access",
    "screen share",
    "anydesk",
    "teamviewer",
)

HIGH_RISK_TERMS = (
    "urgent",
    "immediately",
    "digital arrest",
    "police",
    "income tax",
    "rbi",
    "bank",
    "kyc",
    "courier",
    "parcel",
    "job",
    "investment",
    "refund",
    "lottery",
    "prize",
)


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_phone(
    phone: Any,
) -> str:
    """
    Normalize a phone number for comparison.

    This does not verify whether the number is real or assigned.
    """

    value = str(
        phone or ""
    ).strip()

    if not value:

        return ""

    # Keep a leading + and digits only.
    if value.startswith("+"):

        prefix = "+"

        digits = re.sub(
            r"\D",
            "",
            value[1:],
        )

        return prefix + digits

    return re.sub(
        r"\D",
        "",
        value,
    )


def digits_only(
    phone: Any,
) -> str:
    """
    Return only digits from a phone number.
    """

    return re.sub(
        r"\D",
        "",
        str(phone or ""),
    )


# ============================================================
# BASIC VALIDATION
# ============================================================

def is_plausible_phone(
    phone: Any,
) -> bool:
    """
    Check whether the number has a plausible international length.

    This is syntax checking only.
    """

    digits = digits_only(
        phone
    )

    return 7 <= len(
        digits
    ) <= 15


def is_indian_number(
    phone: Any,
) -> bool:
    """
    Check whether a number appears to use India's country code.

    Accepted examples include:
    +91XXXXXXXXXX
    91XXXXXXXXXX
    0XXXXXXXXXX
    XXXXXXXXXX
    """

    digits = digits_only(
        phone
    )

    if len(digits) == 10:

        return True

    if len(digits) == 11 and digits.startswith("0"):

        return True

    if len(digits) == 12 and digits.startswith("91"):

        return True

    return False


# ============================================================
# NUMBER CLASSIFICATION
# ============================================================

def classify_phone(
    phone: Any,
) -> dict[str, Any]:
    """
    Perform conservative offline phone-number classification.

    Possible statuses:
    - INVALID
    - PLAUSIBLE
    - INDIAN_FORMAT
    """

    normalized = normalize_phone(
        phone
    )

    if not normalized:

        return {
            "status": "INVALID",
            "normalized": "",
            "is_plausible": False,
            "is_indian_format": False,
            "reasons": [
                "No phone number was provided."
            ],
        }

    plausible = is_plausible_phone(
        normalized
    )

    indian = is_indian_number(
        normalized
    )

    if not plausible:

        status = "INVALID"

        reasons = [
            "The phone number length does not look valid."
        ]

    elif indian:

        status = "INDIAN_FORMAT"

        reasons = [
            "The number has a format consistent with an Indian number."
        ]

    else:

        status = "PLAUSIBLE"

        reasons = [
            "The number has a plausible international format."
        ]

    return {
        "status": status,
        "normalized": normalized,
        "is_plausible": plausible,
        "is_indian_format": indian,
        "reasons": reasons,
    }


# ============================================================
# CALL CONTEXT ANALYSIS
# ============================================================

def _find_terms(
    text: str,
    terms: tuple[str, ...],
) -> list[str]:
    """
    Find relevant terms in call context.
    """

    lowered = text.lower()

    return [
        term
        for term in terms
        if term in lowered
    ]


def assess_phone_context(
    phone: Any,
    context: Any = "",
) -> dict[str, Any]:
    """
    Combine basic phone-number information with the user's
    description of the call.

    The context is treated as untrusted user-provided evidence.
    """

    phone_result = classify_phone(
        phone
    )

    text = str(
        context or ""
    ).strip()

    critical = _find_terms(
        text,
        CRITICAL_TERMS,
    )

    high_risk = _find_terms(
        text,
        HIGH_RISK_TERMS,
    )

    reasons = list(
        phone_result.get(
            "reasons",
            [],
        )
    )

    risk = "UNKNOWN"

    if critical:

        risk = "CRITICAL"

        reasons.append(
            "The call description contains a request or topic "
            "associated with highly sensitive credentials or "
            "remote access."
        )

    elif len(high_risk) >= 2:

        risk = "HIGH"

        reasons.append(
            "Multiple scam-related signals appear in the call context."
        )

    elif high_risk:

        risk = "CAUTION"

        reasons.append(
            "The call context contains a potentially suspicious topic."
        )

    else:

        risk = "UNKNOWN"

        reasons.append(
            "A phone number alone cannot establish whether a caller "
            "is trustworthy."
        )

    return {
        "risk": risk,
        "phone": phone_result,
        "critical_terms": critical,
        "high_risk_terms": high_risk,
        "reasons": reasons,
        "disclaimer": (
            "Caller ID and phone numbers can be spoofed. "
            "Treat this result as a safety signal, not proof of identity."
        ),
    }


# ============================================================
# SAFETY ACTIONS
# ============================================================

def get_phone_safety_actions(
    risk: str,
) -> list[str]:
    """
    Return conservative actions based on the assessed risk.
    """

    normalized = str(
        risk or "UNKNOWN"
    ).upper()

    if normalized == "CRITICAL":

        return [
            "Do not share OTP, UPI PIN, ATM PIN, CVV or password.",
            "Do not install remote-access software.",
            "Do not share your screen.",
            "Do not transfer money because of the caller's instructions.",
            "End the call if the caller pressures or threatens you.",
            "Verify the claim independently using an official contact method.",
        ]

    if normalized == "HIGH":

        return [
            "Do not make payments during the call.",
            "Do not share sensitive banking information.",
            "Do not install an app at the caller's request.",
            "Verify the caller independently before taking action.",
        ]

    if normalized == "CAUTION":

        return [
            "Do not rush into any action.",
            "Verify important claims through an official channel.",
            "Never share OTPs, PINs or passwords with callers.",
        ]

    return [
        "If the caller asks for money or sensitive information, stop.",
        "Verify important claims independently.",
        "Never share OTPs, PINs or passwords with callers.",
    ]


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "normalize_phone",
    "digits_only",
    "is_plausible_phone",
    "is_indian_number",
    "classify_phone",
    "assess_phone_context",
    "get_phone_safety_actions",
]
