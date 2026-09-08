"""
ElderShield Deterministic Text Rules

Detects common scam/social-engineering signals from text.

This module is intentionally deterministic:
- No network access
- No AI
- No external API
- No assumptions that an unknown caller is automatically a scam

The results are evidence signals for the Case Engine.
They are not proof of fraud by themselves.
"""

from __future__ import annotations

import re
from typing import Any


# ============================================================
# SIGNAL DEFINITIONS
# ============================================================

SIGNAL_PATTERNS: dict[str, tuple[str, ...]] = {

    "urgency": (
        "urgent",
        "immediately",
        "right now",
        "do it now",
        "act now",
        "within minutes",
        "within 10 minutes",
        "within 15 minutes",
        "last chance",
        "today only",
        "final warning",
        "without delay",
        "as soon as possible",
    ),

    "threat": (
        "account will be blocked",
        "account will be closed",
        "account will be frozen",
        "account is suspended",
        "legal action",
        "police case",
        "arrest",
        "warrant",
        "court case",
        "criminal case",
        "fine will be imposed",
        "penalty will be imposed",
        "you will be arrested",
        "your number will be blocked",
    ),

    "authority_impersonation": (
        "rbi",
        "reserve bank",
        "income tax",
        "income tax department",
        "police",
        "cyber crime",
        "cyber police",
        "customs",
        "courier department",
        "government officer",
        "government department",
        "bank officer",
        "bank manager",
        "sbi officer",
        "uidai",
        "aadhaar department",
        "epfo",
        "income tax officer",
    ),

    "financial_request": (
        "send money",
        "transfer money",
        "transfer funds",
        "make payment",
        "pay now",
        "pay immediately",
        "deposit money",
        "security deposit",
        "processing fee",
        "registration fee",
        "verification fee",
        "activation fee",
        "clearance fee",
        "customs fee",
        "tax payment",
        "pay tax",
        "investment amount",
    ),

    "credential_request": (
        "otp",
        "one time password",
        "upi pin",
        "upi password",
        "atm pin",
        "debit card pin",
        "credit card pin",
        "card pin",
        "cvv",
        "password",
        "login password",
        "banking password",
        "net banking",
        "internet banking",
        "account credentials",
        "login details",
    ),

    "remote_access": (
        "anydesk",
        "teamviewer",
        "remote access",
        "remote control",
        "screen share",
        "share your screen",
        "screenshare",
        "install this app",
        "download this application",
        "install application",
        "give me access to your phone",
        "give remote access",
    ),

    "secrecy": (
        "do not tell anyone",
        "don't tell anyone",
        "keep this secret",
        "do not tell your family",
        "don't tell your family",
        "do not disconnect",
        "don't disconnect",
        "stay on the call",
        "do not speak to anyone",
        "do not contact the bank",
    ),

    "digital_arrest": (
        "digital arrest",
        "digital custody",
        "video arrest",
        "online arrest",
        "money laundering case",
        "money laundering",
        "terrorist financing",
        "drug trafficking case",
        "sim card case",
        "parcel case",
        "illegal parcel",
    ),

    "investment": (
        "guaranteed return",
        "guaranteed profit",
        "guaranteed income",
        "double your money",
        "triple your money",
        "risk free investment",
        "risk-free investment",
        "high return",
        "high returns",
        "investment opportunity",
        "trading profit",
        "crypto profit",
        "share market profit",
    ),

    "job_scam": (
        "work from home",
        "work-from-home",
        "online job",
        "part time job",
        "part-time job",
        "job opportunity",
        "registration fee for job",
        "security fee for job",
        "training fee",
        "job processing fee",
    ),

    "courier_scam": (
        "parcel",
        "courier",
        "customs",
        "customs department",
        "illegal parcel",
        "drugs in your parcel",
        "passport in your parcel",
        "narcotics",
        "package seized",
    ),

    "prize_scam": (
        "you have won",
        "you won",
        "winner",
        "lottery",
        "prize",
        "lucky draw",
        "cash prize",
        "reward",
        "claim your prize",
        "claim your reward",
    ),

    "kyc_scam": (
        "kyc update",
        "kyc verification",
        "complete kyc",
        "kyc expired",
        "kyc will expire",
        "pan verification",
        "aadhaar verification",
        "account verification",
        "verify your account",
        "verify bank account",
    ),

    "qr_payment": (
        "scan qr",
        "scan the qr",
        "scan this qr",
        "qr code",
        "upi qr",
        "receive payment",
        "collect payment",
        "approve collect request",
        "payment request",
    ),
}


# ============================================================
# DANGEROUS ACTION PATTERNS
# ============================================================

DANGEROUS_ACTION_PATTERNS: dict[str, tuple[str, ...]] = {

    "OTP": (
        "otp",
        "one time password",
        "one-time password",
    ),

    "UPI PIN": (
        "upi pin",
        "upi password",
    ),

    "ATM PIN": (
        "atm pin",
        "debit card pin",
        "credit card pin",
        "card pin",
    ),

    "PASSWORD": (
        "password",
        "login password",
        "banking password",
    ),

    "CVV": (
        "cvv",
        "card security code",
    ),

    "BANK CREDENTIALS": (
        "banking credentials",
        "login details",
        "net banking details",
        "internet banking details",
        "bank account details",
    ),

    "REMOTE ACCESS": (
        "anydesk",
        "teamviewer",
        "remote access",
        "remote control",
        "screen share",
        "share your screen",
        "give me access to your phone",
    ),

    "INSTALL APP": (
        "install this app",
        "install the app",
        "download this app",
        "download the application",
        "install application",
    ),

    "SCAN QR": (
        "scan qr",
        "scan the qr",
        "scan this qr",
        "scan qr code",
    ),

    "MONEY TRANSFER": (
        "send money",
        "transfer money",
        "transfer funds",
        "send funds",
        "deposit money",
        "make payment",
        "pay now",
        "pay immediately",
    ),

    "PAYMENT APPROVAL": (
        "approve payment",
        "approve the payment",
        "approve collect request",
        "accept payment request",
        "payment request",
    ),
}


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_text(
    text: str,
) -> str:
    """
    Normalize text for deterministic matching.
    """

    value = str(
        text or ""
    ).lower()

    value = value.replace(
        "\u2019",
        "'",
    )

    value = value.replace(
        "\u2018",
        "'",
    )

    value = value.replace(
        "\u201c",
        '"',
    )

    value = value.replace(
        "\u201d",
        '"',
    )

    value = re.sub(
        r"\s+",
        " ",
        value,
    )

    return value.strip()


# ============================================================
# SIGNAL DETECTION
# ============================================================

def detect_signal_groups(
    text: str,
) -> dict[str, list[str]]:
    """
    Detect scam/social-engineering signal groups.

    Returns only matched phrases.
    """

    normalized = normalize_text(
        text
    )

    results: dict[str, list[str]] = {}

    if not normalized:
        return results

    for group, patterns in SIGNAL_PATTERNS.items():

        matches: list[str] = []

        for pattern in patterns:

            if pattern in normalized:

                matches.append(
                    pattern
                )

        if matches:

            results[group] = list(
                dict.fromkeys(
                    matches
                )
            )

    return results


# ============================================================
# DANGEROUS ACTION DETECTION
# ============================================================

def detect_dangerous_actions(
    text: str,
) -> list[str]:
    """
    Detect requests involving sensitive information or
    high-risk actions.
    """

    normalized = normalize_text(
        text
    )

    if not normalized:
        return []

    actions: list[str] = []

    for action, patterns in DANGEROUS_ACTION_PATTERNS.items():

        for pattern in patterns:

            if pattern in normalized:

                actions.append(
                    action
                )

                break

    return actions


# ============================================================
# CATEGORY DETECTION
# ============================================================

CATEGORY_HINTS: dict[str, tuple[str, ...]] = {

    "bank_kyc": (
        "kyc",
        "bank account",
        "account blocked",
        "account freeze",
        "account frozen",
        "account verification",
        "bank officer",
        "bank manager",
    ),

    "remote_access": (
        "anydesk",
        "teamviewer",
        "remote access",
        "screen share",
        "screen sharing",
        "remote control",
    ),

    "digital_arrest": (
        "digital arrest",
        "digital custody",
        "police",
        "cyber crime",
        "money laundering",
        "warrant",
        "arrest",
    ),

    "courier": (
        "courier",
        "parcel",
        "customs",
        "package seized",
    ),

    "job": (
        "job",
        "work from home",
        "part time job",
        "registration fee",
        "security fee",
    ),

    "investment": (
        "investment",
        "guaranteed return",
        "guaranteed profit",
        "trading profit",
        "double your money",
    ),

    "prize": (
        "lottery",
        "prize",
        "winner",
        "lucky draw",
        "cash prize",
        "reward",
    ),

    "payment_qr": (
        "scan qr",
        "qr code",
        "upi qr",
        "payment request",
        "approve payment",
    ),
}


def detect_categories(
    text: str,
) -> list[str]:
    """
    Detect likely scam categories.
    """

    normalized = normalize_text(
        text
    )

    if not normalized:
        return []

    categories: list[str] = []

    for category, patterns in CATEGORY_HINTS.items():

        if any(
            pattern in normalized
            for pattern in patterns
        ):

            categories.append(
                category
            )

    return categories


# ============================================================
# RISK ESTIMATION
# ============================================================

def estimate_text_risk(
    text: str,
) -> dict[str, Any]:
    """
    Estimate risk from deterministic signals.

    This is intentionally conservative and is not a claim
    that the text is definitely fraudulent.
    """

    signal_groups = detect_signal_groups(
        text
    )

    dangerous_actions = detect_dangerous_actions(
        text
    )

    categories = detect_categories(
        text
    )

    group_count = len(
        signal_groups
    )

    action_count = len(
        dangerous_actions
    )

    # --------------------------------------------------------
    # Critical actions
    # --------------------------------------------------------

    critical_actions = {
        "OTP",
        "UPI PIN",
        "ATM PIN",
        "PASSWORD",
        "CVV",
        "BANK CREDENTIALS",
        "REMOTE ACCESS",
        "MONEY TRANSFER",
        "PAYMENT APPROVAL",
    }

    if any(
        action in critical_actions
        for action in dangerous_actions
    ):

        risk = "CRITICAL"

    # --------------------------------------------------------
    # Multiple independent scam signals
    # --------------------------------------------------------

    elif (
        group_count >= 3
        or (
            group_count >= 2
            and action_count >= 1
        )
    ):

        risk = "HIGH RISK"

    # --------------------------------------------------------
    # One significant signal
    # --------------------------------------------------------

    elif (
        group_count >= 1
        or action_count >= 1
    ):

        risk = "CAUTION"

    else:

        risk = "SAFE"

    return {
        "risk": risk,
        "signal_groups": signal_groups,
        "dangerous_actions": dangerous_actions,
        "categories": categories,
    }


# ============================================================
# HUMAN-READABLE REASONS
# ============================================================

SIGNAL_DESCRIPTIONS = {
    "urgency": "The message creates pressure to act quickly.",
    "threat": "The message uses threats or fear.",
    "authority_impersonation": "The sender appears to invoke an authority or organization.",
    "financial_request": "The message asks for money or payment.",
    "credential_request": "The message asks for sensitive credentials or authentication information.",
    "remote_access": "The message asks for remote access, screen sharing or application installation.",
    "secrecy": "The message asks the person to keep the situation secret or avoid verification.",
    "digital_arrest": "The message contains language associated with digital-arrest scams.",
    "investment": "The message contains investment or guaranteed-return signals.",
    "job_scam": "The message contains possible job-scam signals.",
    "courier_scam": "The message contains courier/customs scam signals.",
    "prize_scam": "The message contains prize or lottery scam signals.",
    "kyc_scam": "The message contains KYC/account-verification scam signals.",
    "qr_payment": "The message contains QR or payment-request signals.",
}


def build_signal_reasons(
    signal_groups: dict[str, list[str]],
) -> list[str]:
    """
    Convert signal groups into short human-readable reasons.
    """

    reasons: list[str] = []

    for group in signal_groups:

        description = SIGNAL_DESCRIPTIONS.get(
            group
        )

        if description:
            reasons.append(
                description
            )

    return reasons


# ============================================================
# COMPLETE ANALYSIS
# ============================================================

def analyze_text_rules(
    text: str,
) -> dict[str, Any]:
    """
    Run all deterministic text rules.
    """

    result = estimate_text_risk(
        text
    )

    reasons = build_signal_reasons(
        result["signal_groups"]
    )

    return {
        "risk": result["risk"],
        "signal_groups": result["signal_groups"],
        "dangerous_actions": result["dangerous_actions"],
        "categories": result["categories"],
        "reasons": reasons,
    }
