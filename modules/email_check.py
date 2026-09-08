"""
ElderShield Email Safety Checks

Conservative offline checks for suspicious email content.

This module does not:
- Send email anywhere
- Access the user's mailbox
- Open attachments
- Execute files
- Visit links
- Verify the real identity of a sender

Email content is treated as untrusted evidence.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


# ============================================================
# CONSTANTS
# ============================================================

MAX_EMAIL_TEXT_LENGTH = 30_000
MAX_EMAIL_ADDRESS_LENGTH = 320

FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
}

HIGH_RISK_TERMS = (
    "urgent",
    "immediately",
    "act now",
    "account blocked",
    "account suspended",
    "verify your account",
    "verify immediately",
    "kyc",
    "otp",
    "upi pin",
    "atm pin",
    "cvv",
    "password",
    "refund",
    "payment",
    "transfer money",
    "pay now",
    "processing fee",
    "security deposit",
    "digital arrest",
    "police",
    "income tax",
    "rbi",
    "bank",
    "lottery",
    "prize",
    "job offer",
    "investment",
)

DANGEROUS_TERMS = (
    "share otp",
    "send otp",
    "tell me your otp",
    "share your pin",
    "send your pin",
    "share your password",
    "send your password",
    "click the link",
    "open the attachment",
    "install this app",
    "download this app",
    "remote access",
    "screen sharing",
    "anydesk",
    "teamviewer",
)

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE,
)


# ============================================================
# EMAIL ADDRESS
# ============================================================

def normalize_email(
    email: Any,
) -> str:
    """
    Normalize an email address for analysis.
    """

    value = str(
        email or ""
    ).strip().lower()

    return value


def is_valid_email_format(
    email: Any,
) -> bool:
    """
    Perform basic email syntax validation.

    This does not verify that the mailbox exists.
    """

    value = normalize_email(
        email
    )

    if not value:

        return False

    if len(value) > MAX_EMAIL_ADDRESS_LENGTH:

        return False

    pattern = (
        r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+"
        r"@"
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
    )

    return bool(
        re.match(
            pattern,
            value,
        )
    )


def get_email_domain(
    email: Any,
) -> str:
    """
    Extract the domain portion of an email address.
    """

    value = normalize_email(
        email
    )

    if "@" not in value:

        return ""

    return value.rsplit(
        "@",
        1,
    )[1]


def is_free_email_domain(
    email: Any,
) -> bool:
    """
    Determine whether the address uses a common free-email provider.

    A free email provider is NOT inherently suspicious.
    """

    domain = get_email_domain(
        email
    )

    return domain in FREE_EMAIL_DOMAINS


# ============================================================
# SUSPICIOUS DOMAIN SIGNALS
# ============================================================

def domain_signals(
    domain: Any,
) -> list[str]:
    """
    Identify structural warning signs in an email domain.
    """

    value = str(
        domain or ""
    ).strip().lower()

    if not value:

        return []

    signals: list[str] = []

    if value.startswith("xn--") or ".xn--" in value:

        signals.append(
            "punycode_domain"
        )

    if value.count(".") >= 3:

        signals.append(
            "many_subdomains"
        )

    if "-" in value:

        signals.append(
            "hyphenated_domain"
        )

    suspicious_words = (
        "secure",
        "verify",
        "support",
        "account",
        "refund",
        "update",
        "login",
        "banking",
        "official",
    )

    if any(
        word in value
        for word in suspicious_words
    ):

        signals.append(
            "suspicious_keyword_in_domain"
        )

    return signals


# ============================================================
# TEXT ANALYSIS
# ============================================================

def _find_terms(
    text: str,
    terms: tuple[str, ...],
) -> list[str]:
    """
    Find terms in email text.
    """

    lowered = text.lower()

    return [
        term
        for term in terms
        if term in lowered
    ]


def extract_urls(
    text: Any,
) -> list[str]:
    """
    Extract HTTP/HTTPS URLs from email text.

    URLs are returned as untrusted strings.
    """

    value = str(
        text or ""
    )

    urls = URL_PATTERN.findall(
        value
    )

    cleaned: list[str] = []

    for url in urls:

        url = url.rstrip(
            ".,;:!?)]}"
        )

        if url not in cleaned:

            cleaned.append(
                url
            )

    return cleaned[:20]


def analyze_email_text(
    text: Any,
    sender: Any = "",
) -> dict[str, Any]:
    """
    Analyze email content using deterministic rules.

    Returns a structured result suitable for case_engine.py.
    """

    raw_text = str(
        text or ""
    ).strip()

    if len(raw_text) > MAX_EMAIL_TEXT_LENGTH:

        raw_text = raw_text[
            :MAX_EMAIL_TEXT_LENGTH
        ]

    sender_value = normalize_email(
        sender
    )

    reasons: list[str] = []
    dangerous_actions: list[str] = []
    signal_groups: list[str] = []
    urls = extract_urls(
        raw_text
    )

    high_risk = _find_terms(
        raw_text,
        HIGH_RISK_TERMS,
    )

    dangerous = _find_terms(
        raw_text,
        DANGEROUS_TERMS,
    )

    # --------------------------------------------------------
    # Sender analysis
    # --------------------------------------------------------

    sender_valid = (
        is_valid_email_format(
            sender_value
        )
        if sender_value
        else False
    )

    sender_domain = get_email_domain(
        sender_value
    )

    sender_domain_signals = domain_signals(
        sender_domain
    )

    if sender_value and not sender_valid:

        reasons.append(
            "The supplied sender address does not have a normal email format."
        )

        signal_groups.append(
            "sender_anomaly"
        )

    if sender_domain_signals:

        reasons.append(
            "The sender domain has structural characteristics "
            "that deserve additional verification."
        )

        signal_groups.append(
            "sender_anomaly"
        )

    # --------------------------------------------------------
    # Content analysis
    # --------------------------------------------------------

    if high_risk:

        reasons.append(
            "The email contains scam-related or high-pressure language."
        )

        signal_groups.append(
            "suspicious_content"
        )

    if dangerous:

        reasons.append(
            "The email appears to request or encourage a dangerous action."
        )

        signal_groups.append(
            "dangerous_action"
        )

    # --------------------------------------------------------
    # URL analysis
    # --------------------------------------------------------

    if urls:

        reasons.append(
            "The email contains one or more links that should be "
            "checked before opening."
        )

        signal_groups.append(
            "embedded_url"
        )

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    risk = "UNKNOWN"

    if dangerous:

        risk = "CRITICAL"

        dangerous_actions.extend(
            dangerous
        )

    elif len(signal_groups) >= 2:

        risk = "HIGH"

    elif high_risk or urls:

        risk = "CAUTION"

    else:

        risk = "UNKNOWN"

    # --------------------------------------------------------
    # Safe actions
    # --------------------------------------------------------

    recommended_actions = [
        "Do not share OTPs, PINs, passwords or banking credentials.",
        "Do not send money because of an email request.",
        "Do not open unexpected attachments.",
        "Verify important claims using an official website or phone number.",
    ]

    if urls:

        recommended_actions.insert(
            0,
            "Do not open a suspicious link until its destination has been verified.",
        )

    if dangerous:

        recommended_actions.insert(
            0,
            "Stop the requested action and verify the sender independently.",
        )

    return {
        "risk": risk,
        "summary": (
            "Email content was checked for common phishing and "
            "social-engineering signals."
        ),
        "reasons": reasons,
        "dangerous_actions": dangerous_actions,
        "signal_groups": list(
            dict.fromkeys(
                signal_groups
            )
        ),
        "urls": urls,
        "sender": sender_value,
        "sender_domain": sender_domain,
        "sender_domain_signals": sender_domain_signals,
        "high_risk_terms": high_risk,
        "dangerous_terms": dangerous,
        "recommended_actions": recommended_actions,
        "disclaimer": (
            "Email analysis provides safety signals only. "
            "It does not prove sender identity or guarantee that an "
            "email is safe."
        ),
    }


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "MAX_EMAIL_TEXT_LENGTH",
    "MAX_EMAIL_ADDRESS_LENGTH",
    "normalize_email",
    "is_valid_email_format",
    "get_email_domain",
    "is_free_email_domain",
    "domain_signals",
    "extract_urls",
    "analyze_email_text",
]
