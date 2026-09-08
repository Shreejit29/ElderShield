"""
ElderShield Case Engine

Central evidence-correlation and risk-assessment layer.

The case engine combines:
- deterministic text signals
- scam knowledge
- URL analysis
- organization verification
- AI analysis
- dangerous actions
- cross-channel evidence

Design principle:

    EVIDENCE
        ↓
    CORRELATION
        ↓
    RISK
        ↓
    INTERVENTION

IMPORTANT:
This engine is a safety aid, not a guarantee of legitimacy.
When evidence is incomplete or conflicting, it should prefer
caution over false reassurance.
"""

from __future__ import annotations

import re
from typing import Any

from modules.intervention import (
    get_intervention,
    escalate_risk_for_actions,
)
from modules.knowledge import (
    find_dangerous_actions,
    search_categories,
)
from modules.url_analyzer import analyze_url
from modules.official_verify import verify_organization


# ============================================================
# RISK ORDER
# ============================================================

RISK_ORDER = {
    "SAFE": 0,
    "CAUTION": 1,
    "HIGH RISK": 2,
    "CRITICAL": 3,
    "UNKNOWN": 1,
}


# ============================================================
# CRITICAL SIGNALS
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
    "investment payment",
    "registration payment",
    "joining fee",
    "security deposit",
    "tax payment",
    "processing fee",
}


# ============================================================
# TEXT SIGNALS
# ============================================================

TEXT_SIGNAL_GROUPS = {

    "urgency": [
        "urgent",
        "immediately",
        "right now",
        "today",
        "within one hour",
        "last warning",
        "act now",
        "quickly",
        "do not delay",
    ],

    "threat": [
        "arrest",
        "police case",
        "warrant",
        "legal action",
        "account blocked",
        "account suspended",
        "penalty",
        "fine",
        "court case",
        "cyber crime",
    ],

    "authority_impersonation": [
        "bank officer",
        "bank representative",
        "police officer",
        "government officer",
        "income tax officer",
        "rbi officer",
        "customs officer",
        "cyber crime officer",
        "court officer",
    ],

    "financial_request": [
        "send money",
        "transfer money",
        "pay",
        "payment",
        "deposit",
        "fee",
        "charge",
        "refund",
        "investment",
        "upi",
    ],

    "credential_request": [
        "otp",
        "upi pin",
        "atm pin",
        "password",
        "card number",
        "cvv",
        "verification code",
        "bank details",
        "account number",
    ],

    "remote_access": [
        "anydesk",
        "teamviewer",
        "remote access",
        "remote control",
        "screen sharing",
        "share your screen",
        "install this app",
        "install application",
    ],

    "secrecy": [
        "don't tell anyone",
        "do not tell anyone",
        "keep this secret",
        "don't tell your family",
        "do not tell your family",
        "stay on the call",
        "do not disconnect",
    ],
}


# ============================================================
# HELPERS
# ============================================================

def normalize_text(
    text: Any,
) -> str:
    """
    Normalize arbitrary text for deterministic analysis.
    """

    if not isinstance(text, str):
        return ""

    return re.sub(
        r"\s+",
        " ",
        text.lower().strip(),
    )


def collect_text(evidence: dict[str, Any]) -> str:
    """
    Collect relevant text from a case.

    The function intentionally handles only known fields.
    """

    text_parts = []

    fields = [
        "message_text",
        "call_description",
        "transcript",
        "text",
        "ocr_text",
        "summary",
    ]

    for field in fields:

        value = evidence.get(field)

        if isinstance(value, str) and value.strip():

            text_parts.append(value)

    # AI screen analysis may contain textual fields.
    screen_analysis = evidence.get(
        "screen_analysis"
    )

    if isinstance(screen_analysis, dict):

        for field in [
            "summary",
            "text",
            "ocr_text",
            "transcript",
        ]:

            value = screen_analysis.get(field)

            if isinstance(value, str):
                text_parts.append(value)

    # AI audio analysis may contain a transcript.
    audio_analysis = evidence.get(
        "audio_analysis"
    )

    if isinstance(audio_analysis, dict):

        for field in [
            "summary",
            "transcript",
            "text",
        ]:

            value = audio_analysis.get(field)

            if isinstance(value, str):
                text_parts.append(value)

    return "\n".join(text_parts)


def highest_risk(
    risks: list[str],
) -> str:
    """
    Return the highest risk level in a collection.
    """

    if not risks:
        return "UNKNOWN"

    valid_risks = [
        risk
        for risk in risks
        if risk in RISK_ORDER
    ]

    if not valid_risks:
        return "UNKNOWN"

    return max(
        valid_risks,
        key=lambda value: RISK_ORDER[value],
    )


def extract_actions_from_text(
    text: str,
) -> list[str]:
    """
    Extract dangerous actions from deterministic text analysis.
    """

    normalized = normalize_text(
        text
    )

    actions = set()

    action_patterns = {
        "OTP": [
            r"\botp\b",
            r"one time password",
            r"verification code",
        ],

        "UPI PIN": [
            r"upi pin",
            r"upi.*pin",
        ],

        "ATM PIN": [
            r"atm pin",
            r"atm.*pin",
        ],

        "password": [
            r"\bpassword\b",
            r"login password",
        ],

        "remote access": [
            r"remote access",
            r"remote control",
            r"anydesk",
            r"teamviewer",
            r"screen sharing",
            r"share your screen",
        ],

        "install application": [
            r"install this app",
            r"install application",
            r"download this app",
            r"install an app",
        ],

        "money transfer": [
            r"transfer money",
            r"send money",
            r"transfer.*amount",
            r"send.*₹",
            r"send.*rs",
            r"send.*rupees",
        ],

        "payment": [
            r"make a payment",
            r"approve payment",
            r"payment request",
            r"pay.*fee",
            r"pay.*charge",
        ],

        "scan QR": [
            r"scan.*qr",
            r"qr.*code",
        ],
    }

    for action, patterns in action_patterns.items():

        for pattern in patterns:

            if re.search(
                pattern,
                normalized,
            ):

                actions.add(action)
                break

    # Knowledge-base actions provide additional coverage.
    knowledge_actions = find_dangerous_actions(
        text
    )

    for action in knowledge_actions:

        actions.add(action)

    return sorted(actions)


def detect_signal_groups(
    text: str,
) -> dict[str, list[str]]:
    """
    Detect deterministic scam-signal groups.
    """

    normalized = normalize_text(
        text
    )

    detected = {}

    for group, phrases in TEXT_SIGNAL_GROUPS.items():

        matches = []

        for phrase in phrases:

            if phrase.lower() in normalized:
                matches.append(phrase)

        if matches:
            detected[group] = matches

    return detected


def detect_categories(
    text: str,
) -> list[dict[str, Any]]:
    """
    Find matching scam categories from the knowledge base.
    """

    if not text.strip():
        return []

    return search_categories(
        text
    )


# ============================================================
# AI RESULT EXTRACTION
# ============================================================

def extract_ai_risk(
    analysis: Any,
) -> str | None:
    """
    Extract a normalized risk level from an AI analysis result.

    AI output is treated as untrusted evidence, not as an
    unquestionable decision.
    """

    if not isinstance(analysis, dict):
        return None

    possible_fields = [
        "risk",
        "risk_level",
        "severity",
    ]

    for field in possible_fields:

        value = analysis.get(field)

        if not isinstance(value, str):
            continue

        normalized = value.strip().upper()

        if normalized == "HIGH":
            normalized = "HIGH RISK"

        if normalized == "HIGH_RISK":
            normalized = "HIGH RISK"

        if normalized in RISK_ORDER:
            return normalized

    return None


def extract_ai_actions(
    analysis: Any,
) -> list[str]:
    """
    Extract dangerous actions identified by AI.
    """

    if not isinstance(analysis, dict):
        return []

    fields = [
        "dangerous_actions",
        "requested_actions",
        "actions",
    ]

    actions = []

    for field in fields:

        value = analysis.get(field)

        if not isinstance(value, list):
            continue

        for item in value:

            if isinstance(item, str):
                actions.append(item)

    return actions


def extract_ai_reasons(
    analysis: Any,
) -> list[str]:
    """
    Extract explanation signals from AI output.
    """

    if not isinstance(analysis, dict):
        return []

    reasons = []

    for field in [
        "reasons",
        "risk_factors",
        "indicators",
    ]:

        value = analysis.get(field)

        if isinstance(value, list):

            for item in value:

                if isinstance(item, str):
                    reasons.append(item)

    return reasons


# ============================================================
# CASE ENGINE
# ============================================================

def analyze_case(
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """
    Analyze a complete ElderShield evidence case.

    Expected evidence may include:

        {
            "channel": "message",
            "message_text": "...",
            "url": "...",
            "organization": "...",
            "screen_analysis": {...},
            "audio_analysis": {...},
            "already_paid": False,
            "remote_access_granted": False
        }

    Returns a standardized ElderShield result.
    """

    if not isinstance(evidence, dict):

        return {
            "risk": "UNKNOWN",
            "summary": (
                "The evidence could not be processed safely."
            ),
            "reasons": [],
            "actions": [
                "Do not take financial action until verified."
            ],
        }

    # --------------------------------------------------------
    # Gather text
    # --------------------------------------------------------

    combined_text = collect_text(
        evidence
    )

    # --------------------------------------------------------
    # Deterministic signals
    # --------------------------------------------------------

    signal_groups = detect_signal_groups(
        combined_text
    )

    categories = detect_categories(
        combined_text
    )

    dangerous_actions = extract_actions_from_text(
        combined_text
    )

    # --------------------------------------------------------
    # AI evidence
    # --------------------------------------------------------

    ai_analyses = []

    screen_analysis = evidence.get(
        "screen_analysis"
    )

    if isinstance(screen_analysis, dict):
        ai_analyses.append(
            screen_analysis
        )

    audio_analysis = evidence.get(
        "audio_analysis"
    )

    if isinstance(audio_analysis, dict):
        ai_analyses.append(
            audio_analysis
        )

    ai_risks = []

    ai_reasons = []

    for analysis in ai_analyses:

        ai_risk = extract_ai_risk(
            analysis
        )

        if ai_risk:
            ai_risks.append(
                ai_risk
            )

        ai_reasons.extend(
            extract_ai_reasons(
                analysis
            )
        )

        dangerous_actions.extend(
            extract_ai_actions(
                analysis
            )
        )

    # --------------------------------------------------------
    # Normalize actions
    # --------------------------------------------------------

    normalized_actions = []

    seen_actions = set()

    for action in dangerous_actions:

        if not isinstance(action, str):
            continue

        cleaned = action.strip()

        if not cleaned:
            continue

        key = cleaned.lower()

        if key in seen_actions:
            continue

        seen_actions.add(key)

        normalized_actions.append(
            cleaned
        )

    dangerous_actions = normalized_actions

    normalized_action_keys = {
        action.lower()
        for action in dangerous_actions
    }

    # --------------------------------------------------------
    # URL evidence
    # --------------------------------------------------------

    url_result = None

    supplied_url = evidence.get(
        "url"
    )

    if isinstance(supplied_url, str) and supplied_url.strip():

        url_result = analyze_url(
            supplied_url.strip()
        )

    # --------------------------------------------------------
    # Organization verification
    # --------------------------------------------------------

    organization_result = None

    organization = evidence.get(
        "organization"
    )

    domain = None

    if url_result:
        domain = url_result.get(
            "domain"
        )

    if organization and domain:

        organization_result = verify_organization(
            organization,
            domain,
        )

    # --------------------------------------------------------
    # Determine baseline risk
    # --------------------------------------------------------

    risks = []

    risks.extend(
        ai_risks
    )

    if url_result:

        risks.append(
            url_result.get(
                "risk",
                "UNKNOWN",
            )
        )

    # Strong deterministic signal groups.
    signal_group_names = set(
        signal_groups.keys()
    )

    if "credential_request" in signal_group_names:

        risks.append(
            "CRITICAL"
        )

    if "remote_access" in signal_group_names:

        risks.append(
            "HIGH RISK"
        )

    if "financial_request" in signal_group_names:

        risks.append(
            "HIGH RISK"
        )

    if "threat" in signal_group_names:

        risks.append(
            "HIGH RISK"
        )

    if "secrecy" in signal_group_names:

        risks.append(
            "HIGH RISK"
        )

    # Category matches.
    if categories:

        risks.append(
            "CAUTION"
        )

    # Organization mismatch.
    if organization_result:

        if organization_result.get(
            "status"
        ) == "MISMATCH":

            risks.append(
                "HIGH RISK"
            )

    baseline_risk = highest_risk(
        risks
    )

    # --------------------------------------------------------
    # Cross-channel escalation
    # --------------------------------------------------------

    channels = set()

    channel = evidence.get(
        "channel"
    )

    if isinstance(channel, str):
        channels.add(
            channel.lower()
        )

    if evidence.get(
        "message_text"
    ):
        channels.add(
            "message"
        )

    if evidence.get(
        "call_description"
    ):
        channels.add(
            "call"
        )

    if evidence.get(
        "url"
    ):
        channels.add(
            "url"
        )

    if evidence.get(
        "screen_analysis"
    ):
        channels.add(
            "screen"
        )

    if evidence.get(
        "audio_analysis"
    ):
        channels.add(
            "call_audio"
        )

    # Multiple independent scam channels increase confidence.
    scam_signal_present = bool(
        signal_groups
        or categories
        or ai_risks
        or url_result
    )

    if (
        len(channels) >= 2
        and scam_signal_present
    ):

        if baseline_risk == "SAFE":
            baseline_risk = "CAUTION"

        elif baseline_risk == "CAUTION":
            baseline_risk = "HIGH RISK"

    # --------------------------------------------------------
    # Critical-action fail-safe
    # --------------------------------------------------------

    if (
        normalized_action_keys
        & {
            action.lower()
            for action in CRITICAL_ACTIONS
        }
    ):

        baseline_risk = "CRITICAL"

    elif (
        normalized_action_keys
        & {
            action.lower()
            for action in HIGH_RISK_ACTIONS
        }
    ):

        baseline_risk = escalate_risk_for_actions(
            baseline_risk,
            dangerous_actions,
        )

    # --------------------------------------------------------
    # Already paid / remote access
    # --------------------------------------------------------

    already_paid = bool(
        evidence.get(
            "already_paid",
            False,
        )
    )

    remote_access_granted = bool(
        evidence.get(
            "remote_access_granted",
            False,
        )
    )

    if already_paid:

        baseline_risk = "CRITICAL"

    if remote_access_granted:

        baseline_risk = "CRITICAL"

    # --------------------------------------------------------
    # Build reasons
    # --------------------------------------------------------

    reasons = []

    if signal_groups:

        for group, matches in signal_groups.items():

            readable_group = group.replace(
                "_",
                " ",
            ).title()

            reasons.append(
                f"{readable_group} signals detected."
            )

    for category in categories:

        name = category.get(
            "name",
            category.get(
                "category",
                "Unknown",
            ),
        )

        reasons.append(
            f"Pattern resembles {name}."
        )

    if url_result:

        reasons.extend(
            url_result.get(
                "reasons",
                [],
            )
        )

    if organization_result:

        if organization_result.get(
            "status"
        ) == "MISMATCH":

            reasons.append(
                organization_result.get(
                    "message",
                    "Organization/domain mismatch detected.",
                )
            )

        elif organization_result.get(
            "status"
        ) == "MATCH":

            reasons.append(
                "The supplied domain matches the current "
                "official-domain registry."
            )

    reasons.extend(
        ai_reasons
    )

    for action in dangerous_actions:

        reasons.append(
            f"Potentially dangerous action detected: {action}."
        )

    # Deduplicate reasons.
    cleaned_reasons = []

    seen_reasons = set()

    for reason in reasons:

        if not isinstance(reason, str):
            continue

        cleaned = reason.strip()

        if not cleaned:
            continue

        key = cleaned.lower()

        if key in seen_reasons:
            continue

        seen_reasons.add(key)

        cleaned_reasons.append(
            cleaned
        )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    if baseline_risk == "CRITICAL":

        summary = (
            "ElderShield detected one or more high-impact "
            "warning signals. Do not continue with the requested "
            "action until you independently verify the situation."
        )

    elif baseline_risk == "HIGH RISK":

        summary = (
            "ElderShield detected significant scam or social-"
            "engineering warning signals. Do not make payments, "
            "share sensitive information or install software "
            "until the request is independently verified."
        )

    elif baseline_risk == "CAUTION":

        summary = (
            "ElderShield detected warning signs that deserve "
            "careful verification before you take action."
        )

    elif baseline_risk == "SAFE":

        summary = (
            "ElderShield did not detect strong scam indicators "
            "in the available evidence. This does not prove "
            "that the situation is legitimate."
        )

    else:

        summary = (
            "ElderShield could not confidently determine the "
            "risk. Avoid financial action until you can verify "
            "the situation independently."
        )

    # --------------------------------------------------------
    # Intervention
    # --------------------------------------------------------

    intervention = get_intervention(
        risk=baseline_risk,
        dangerous_actions=dangerous_actions,
        category=(
            categories[0].get("category")
            if categories
            else None
        ),
        already_paid=already_paid,
        remote_access_granted=remote_access_granted,
    )

    final_risk = intervention.get(
        "risk",
        baseline_risk,
    )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {
        "risk": final_risk,
        "summary": summary,
        "reasons": cleaned_reasons,
        "actions": intervention.get(
            "actions",
            [],
        ),
        "headline": intervention.get(
            "headline",
            "",
        ),
        "priority": intervention.get(
            "priority",
            "MEDIUM",
        ),
        "categories": [
            item.get(
                "category"
            )
            for item in categories
            if item.get("category")
        ],
        "dangerous_actions": dangerous_actions,
        "signal_groups": signal_groups,
        "channels": sorted(channels),
        "url_analysis": url_result,
        "organization_verification": (
            organization_result
        ),
        "ai_risks": ai_risks,
        "ai_reasons": ai_reasons,
        "confidence_note": (
            "Risk is based on the available evidence and "
            "deterministic safety rules. It is not a guarantee "
            "that the content is safe or fraudulent."
        ),
    }
