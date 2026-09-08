"""
ElderShield Payment Safety Checks

Conservative offline analysis for payment-related scam signals.

This module:
- Detects suspicious payment requests.
- Detects QR/payment approval pressure.
- Identifies common payment scam patterns.
- Never initiates a payment.
- Never connects to a bank or UPI provider.
- Never asks for or stores UPI PINs.
- Treats payment instructions as untrusted evidence.

A payment-related warning is a safety signal, not proof of fraud.
"""

from __future__ import annotations

import re
from typing import Any


# ============================================================
# CONSTANTS
# ============================================================

MAX_TEXT_LENGTH = 20_000


PAYMENT_REQUEST_PATTERNS = (
    (
        "money_transfer",
        re.compile(
            r"\b(?:send|transfer|pay|deposit)"
            r"\b.{0,80}\b(?:money|cash|amount|rupees?|₹)\b",
            re.IGNORECASE,
        ),
    ),

    (
        "payment_request",
        re.compile(
            r"\b(?:make|complete|confirm|approve)"
            r"\b.{0,60}\b(?:payment|transaction)\b",
            re.IGNORECASE,
        ),
    ),

    (
        "qr_payment",
        re.compile(
            r"\b(?:scan|use)"
            r"\b.{0,50}\b(?:qr|q\.r\.)\b",
            re.IGNORECASE,
        ),
    ),

    (
        "upi_request",
        re.compile(
            r"\b(?:approve|accept|authorise|authorize)"
            r"\b.{0,80}\b(?:upi|collect|payment request)\b",
            re.IGNORECASE,
        ),
    ),

    (
        "fee_request",
        re.compile(
            r"\b(?:pay|send|deposit)"
            r"\b.{0,80}\b(?:fee|charge|tax|deposit|"
            r"processing|registration|security)\b",
            re.IGNORECASE,
        ),
    ),
)


HIGH_RISK_PAYMENT_PATTERNS = (
    (
        "refund_payment",
        re.compile(
            r"\b(?:refund|cashback|return)"
            r"\b.{0,100}\b(?:pay|send|transfer|fee|charge)\b",
            re.IGNORECASE,
        ),
    ),

    (
        "investment_payment",
        re.compile(
            r"\b(?:investment|trading|profit|returns?)"
            r"\b.{0,100}\b(?:pay|deposit|transfer|fee)\b",
            re.IGNORECASE,
        ),
    ),

    (
        "job_payment",
        re.compile(
            r"\b(?:job|work|employment|offer)"
            r"\b.{0,100}\b(?:fee|deposit|registration|payment)\b",
            re.IGNORECASE,
        ),
    ),

    (
        "prize_payment",
        re.compile(
            r"\b(?:lottery|prize|reward|winner)"
            r"\b.{0,100}\b(?:fee|tax|payment|deposit)\b",
            re.IGNORECASE,
        ),
    ),

    (
        "kyc_payment",
        re.compile(
            r"\b(?:kyc|account|bank)"
            r"\b.{0,100}\b(?:fee|payment|charge|deposit)\b",
            re.IGNORECASE,
        ),
    ),

    (
        "threat_payment",
        re.compile(
            r"\b(?:pay|transfer|send)"
            r"\b.{0,100}\b(?:arrest|police|legal action|"
            r"account blocked|account suspended)\b",
            re.IGNORECASE,
        ),
    ),
)


CRITICAL_PAYMENT_TERMS = (
    "upi pin",
    "upi-pin",
    "atm pin",
    "atm-pin",
    "cvv",
    "otp",
    "password",
    "remote access",
    "screen share",
    "anydesk",
    "teamviewer",
)


# ============================================================
# HELPERS
# ============================================================

def _find_pattern_names(
    text: str,
    patterns: tuple[
        tuple[str, re.Pattern[str]],
        ...,
    ],
) -> list[str]:
    """
    Return names of matched payment patterns.
    """

    matches: list[str] = []

    for name, pattern in patterns:

        try:

            if pattern.search(
                text
            ):

                matches.append(
                    name
                )

        except Exception:

            continue

    return matches


def _find_terms(
    text: str,
    terms: tuple[str, ...],
) -> list[str]:
    """
    Return matching critical terms.
    """

    lowered = text.lower()

    return [
        term
        for term in terms
        if term in lowered
    ]


def extract_amounts(
    text: Any,
) -> list[str]:
    """
    Extract payment amounts for contextual analysis.

    This returns only the amount expression found in the text.
    It does not perform any transaction.
    """

    value = str(
        text or ""
    )

    patterns = (
        r"₹\s?\d+(?:[,\d]*)?(?:\.\d+)?",
        r"\b\d+(?:[,\d]*)?\s*(?:rupees?|rs\.?)\b",
    )

    results: list[str] = []

    for pattern in patterns:

        matches = re.findall(
            pattern,
            value,
            flags=re.IGNORECASE,
        )

        for match in matches:

            cleaned = str(
                match
            ).strip()

            if cleaned not in results:

                results.append(
                    cleaned
                )

    return results[:20]


# ============================================================
# PAYMENT ANALYSIS
# ============================================================

def analyze_payment_text(
    text: Any,
) -> dict[str, Any]:
    """
    Analyze text for suspicious payment-related behavior.
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
            "payment_requested": False,
            "signal_groups": [],
            "reasons": [],
            "dangerous_actions": [],
            "amounts": [],
            "recommended_actions": [
                "Never send money because of an unexpected message or call."
            ],
        }

    payment_patterns = _find_pattern_names(
        value,
        PAYMENT_REQUEST_PATTERNS,
    )

    high_risk_patterns = _find_pattern_names(
        value,
        HIGH_RISK_PAYMENT_PATTERNS,
    )

    critical_terms = _find_terms(
        value,
        CRITICAL_PAYMENT_TERMS,
    )

    amounts = extract_amounts(
        value
    )

    reasons: list[str] = []
    signal_groups: list[str] = []
    dangerous_actions: list[str] = []

    # --------------------------------------------------------
    # Payment request
    # --------------------------------------------------------

    if payment_patterns:

        reasons.append(
            "The content appears to contain instructions to make "
            "or approve a payment."
        )

        signal_groups.append(
            "payment_request"
        )

        dangerous_actions.append(
            "PAYMENT"
        )

    # --------------------------------------------------------
    # High-risk payment context
    # --------------------------------------------------------

    if high_risk_patterns:

        reasons.append(
            "The payment request is associated with a common "
            "scam scenario such as refund, job, investment, prize "
            "or KYC pressure."
        )

        signal_groups.append(
            "scam_payment_context"
        )

    # --------------------------------------------------------
    # Critical credentials
    # --------------------------------------------------------

    if critical_terms:

        reasons.append(
            "The content also references sensitive credentials "
            "or remote-access methods."
        )

        signal_groups.append(
            "credential_or_remote_access"
        )

        if any(
            term in critical_terms
            for term in (
                "otp",
                "upi pin",
                "upi-pin",
                "atm pin",
                "atm-pin",
                "cvv",
                "password",
            )
        ):

            dangerous_actions.append(
                "CREDENTIAL_REQUEST"
            )

        if any(
            term in critical_terms
            for term in (
                "remote access",
                "screen share",
                "anydesk",
                "teamviewer",
            )
        ):

            dangerous_actions.append(
                "REMOTE_ACCESS"
            )

    # --------------------------------------------------------
    # Amount
    # --------------------------------------------------------

    if amounts:

        signal_groups.append(
            "payment_amount"
        )

    # --------------------------------------------------------
    # Risk calculation
    # --------------------------------------------------------

    if critical_terms and payment_patterns:

        risk = "CRITICAL"

    elif critical_terms:

        risk = "CRITICAL"

    elif (
        payment_patterns
        and high_risk_patterns
    ):

        risk = "HIGH"

    elif payment_patterns:

        risk = "CAUTION"

    elif high_risk_patterns:

        risk = "CAUTION"

    else:

        risk = "UNKNOWN"

    # --------------------------------------------------------
    # Actions
    # --------------------------------------------------------

    recommended_actions = [
        "Do not send money because of an unexpected call or message.",
        "Do not approve a UPI payment request you did not initiate.",
        "Never enter your UPI PIN just to receive money.",
        "Verify refunds, jobs, investments and government claims through official channels.",
    ]

    if "qr_payment" in payment_patterns:

        recommended_actions.insert(
            0,
            "Do not scan a QR code merely to receive money.",
        )

    if "fee_request" in payment_patterns:

        recommended_actions.insert(
            0,
            "Do not pay an unexpected registration, processing, security or verification fee.",
        )

    if high_risk_patterns:

        recommended_actions.insert(
            0,
            "Stop and independently verify the payment request before taking action.",
        )

    if critical_terms:

        recommended_actions.insert(
            0,
            "Never share OTPs, UPI PINs, ATM PINs, CVV or passwords.",
        )

    return {
        "risk": risk,
        "payment_requested": bool(
            payment_patterns
        ),
        "signal_groups": list(
            dict.fromkeys(
                signal_groups
            )
        ),
        "payment_patterns": payment_patterns,
        "high_risk_patterns": high_risk_patterns,
        "critical_terms": critical_terms,
        "dangerous_actions": list(
            dict.fromkeys(
                dangerous_actions
            )
        ),
        "amounts": amounts,
        "reasons": reasons,
        "recommended_actions": list(
            dict.fromkeys(
                recommended_actions
            )
        ),
        "disclaimer": (
            "Payment analysis provides safety signals only. "
            "ElderShield does not access or control bank or UPI accounts."
        ),
    }


# ============================================================
# PAYMENT-SPECIFIC REMINDER
# ============================================================

def payment_safety_reminder() -> str:
    """
    Return a simple payment safety reminder.
    """

    return (
        "To receive money, you normally do not need to share "
        "your UPI PIN or approve an unexpected payment request."
    )


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "MAX_TEXT_LENGTH",
    "analyze_payment_text",
    "extract_amounts",
    "payment_safety_reminder",
]
