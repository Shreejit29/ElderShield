"""
ElderShield Safety Report

Converts ElderShield analysis results into a simple,
human-readable safety report.

This module does not perform detection itself.
It presents already-detected evidence and recommended actions.

IMPORTANT:
- Never expose secrets in generated reports.
- Reports should contain safety findings, not passwords,
  OTPs, PINs or other credentials.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


# ============================================================
# RISK CONFIGURATION
# ============================================================

RISK_PRIORITY = {
    "SAFE": 0,
    "UNKNOWN": 1,
    "CAUTION": 2,
    "HIGH RISK": 3,
    "CRITICAL": 4,
}


RISK_HEADLINES = {
    "SAFE": "No obvious scam signal detected",
    "UNKNOWN": "ElderShield could not complete a confident assessment",
    "CAUTION": "Be careful before taking any action",
    "HIGH RISK": "Strong scam warning",
    "CRITICAL": "STOP — possible immediate danger",
}


RISK_INSTRUCTIONS = {
    "SAFE": (
        "No obvious scam signal was detected. "
        "Continue to avoid sharing OTPs, PINs and passwords."
    ),

    "UNKNOWN": (
        "ElderShield could not confidently assess this content. "
        "Do not treat this result as proof that it is safe."
    ),

    "CAUTION": (
        "Slow down and verify the situation independently "
        "before clicking, paying or sharing information."
    ),

    "HIGH RISK": (
        "Do not continue with the requested action until "
        "the sender, caller or organization has been independently verified."
    ),

    "CRITICAL": (
        "Stop the requested action immediately. "
        "Do not share secrets, transfer money or give remote access."
    ),
}


# ============================================================
# HELPERS
# ============================================================

def normalize_risk(
    risk: Any,
) -> str:
    """
    Normalize an ElderShield risk label.
    """

    value = str(
        risk or "UNKNOWN"
    ).strip().upper()

    if value == "HIGH":
        value = "HIGH RISK"

    if value == "HIGH_RISK":
        value = "HIGH RISK"

    if value not in RISK_PRIORITY:

        return "UNKNOWN"

    return value


def unique_strings(
    values: Any,
) -> list[str]:
    """
    Return a clean, deduplicated list of strings.
    """

    if not isinstance(
        values,
        list,
    ):
        return []

    result: list[str] = []

    for value in values:

        if not isinstance(
            value,
            str,
        ):
            continue

        cleaned = value.strip()

        if not cleaned:
            continue

        if cleaned not in result:

            result.append(
                cleaned
            )

    return result


def highest_risk(
    risks: list[str],
) -> str:
    """
    Return the highest ElderShield risk.
    """

    if not risks:

        return "UNKNOWN"

    normalized = [
        normalize_risk(risk)
        for risk in risks
    ]

    return max(
        normalized,
        key=lambda risk: RISK_PRIORITY.get(
            risk,
            1,
        ),
    )


# ============================================================
# SENSITIVE DATA PROTECTION
# ============================================================

SENSITIVE_TERMS = (
    "otp",
    "upi pin",
    "atm pin",
    "password",
    "cvv",
    "card pin",
    "banking password",
)


def redact_sensitive_text(
    text: str,
) -> str:
    """
    Remove obvious secret values from text before putting
    it into a report.

    This is a defensive helper, not a complete DLP system.
    """

    value = str(
        text or ""
    )

    # OTP-like six-digit values.
    value = __import__(
        "re"
    ).sub(
        r"\b\d{6}\b",
        "[REDACTED]",
        value,
    )

    # Four-digit PIN-like values when explicitly labelled.
    value = __import__(
        "re"
    ).sub(
        r"(?i)(otp|upi\s*pin|atm\s*pin|card\s*pin|cvv)"
        r"(\s*(is|:|=|-)?\s*)\d{3,8}",
        r"\1 [REDACTED]",
        value,
    )

    return value


# ============================================================
# REPORT CREATION
# ============================================================

def build_report(
    *,
    risk: str = "UNKNOWN",
    summary: str = "",
    reasons: Any = None,
    actions: Any = None,
    dangerous_actions: Any = None,
    categories: Any = None,
    organizations: Any = None,
    urls: Any = None,
    evidence: Any = None,
    channels: Any = None,
    headline: str = "",
) -> dict[str, Any]:
    """
    Build a standardized ElderShield safety report.

    All input is treated as untrusted analysis data.
    """

    normalized_risk = normalize_risk(
        risk
    )

    clean_reasons = unique_strings(
        reasons
    )

    clean_actions = unique_strings(
        actions
    )

    clean_dangerous_actions = unique_strings(
        dangerous_actions
    )

    clean_categories = unique_strings(
        categories
    )

    clean_organizations = unique_strings(
        organizations
    )

    clean_urls = unique_strings(
        urls
    )

    clean_channels = unique_strings(
        channels
    )

    safe_summary = redact_sensitive_text(
        summary
    )

    safe_headline = redact_sensitive_text(
        headline
    )

    if not safe_headline:

        safe_headline = RISK_HEADLINES[
            normalized_risk
        ]

    if not safe_summary:

        safe_summary = RISK_INSTRUCTIONS[
            normalized_risk
        ]

    # --------------------------------------------------------
    # Never display raw dangerous secrets.
    # --------------------------------------------------------

    clean_dangerous_actions = [
        redact_sensitive_text(
            action
        )
        for action in clean_dangerous_actions
    ]

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    generated_at = datetime.now(
        timezone.utc
    ).isoformat()

    return {
        "version": "1.0",
        "generated_at": generated_at,

        "risk": normalized_risk,

        "headline": safe_headline,

        "summary": safe_summary,

        "reasons": clean_reasons,

        "recommended_actions": clean_actions,

        "dangerous_actions": clean_dangerous_actions,

        "categories": clean_categories,

        "organizations": clean_organizations,

        "urls": clean_urls,

        "channels": clean_channels,

        "evidence": evidence
        if isinstance(
            evidence,
            dict,
        )
        else {},

        "safety_instruction": RISK_INSTRUCTIONS[
            normalized_risk
        ],

        "disclaimer": (
            "ElderShield is a safety aid, not a guarantee. "
            "Independently verify important claims using official channels."
        ),
    }


# ============================================================
# REPORT FROM CASE RESULT
# ============================================================

def report_from_case(
    case_result: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Convert a Case Engine result into a report.
    """

    if not isinstance(
        case_result,
        dict,
    ):

        return build_report(
            risk="UNKNOWN",
            summary=(
                "No valid case analysis was available."
            ),
            actions=[
                "Do not take financial action until verified."
            ],
        )

    return build_report(
        risk=case_result.get(
            "risk",
            "UNKNOWN",
        ),

        summary=case_result.get(
            "summary",
            "",
        ),

        reasons=case_result.get(
            "reasons",
            [],
        ),

        actions=case_result.get(
            "actions",
            case_result.get(
                "recommended_actions",
                [],
            ),
        ),

        dangerous_actions=case_result.get(
            "dangerous_actions",
            [],
        ),

        categories=case_result.get(
            "categories",
            [],
        ),

        organizations=case_result.get(
            "organizations",
            [],
        ),

        urls=case_result.get(
            "urls",
            [],
        ),

        evidence=case_result.get(
            "evidence",
            {},
        ),

        channels=case_result.get(
            "channels",
            [],
        ),

        headline=case_result.get(
            "headline",
            "",
        ),
    )


# ============================================================
# SIMPLE TEXT FORMAT
# ============================================================

def report_to_text(
    report: dict[str, Any],
) -> str:
    """
    Convert a report into plain text suitable for display,
    copying or future export.
    """

    if not isinstance(
        report,
        dict,
    ):

        return "No report available."

    risk = normalize_risk(
        report.get(
            "risk",
            "UNKNOWN",
        )
    )

    headline = str(
        report.get(
            "headline",
            RISK_HEADLINES[risk],
        )
    )

    summary = str(
        report.get(
            "summary",
            "",
        )
    )

    reasons = unique_strings(
        report.get(
            "reasons",
            [],
        )
    )

    actions = unique_strings(
        report.get(
            "recommended_actions",
            [],
        )
    )

    dangerous_actions = unique_strings(
        report.get(
            "dangerous_actions",
            [],
        )
    )

    categories = unique_strings(
        report.get(
            "categories",
            [],
        )
    )

    lines: list[str] = []

    lines.append(
        "ELDERSHIELD SAFETY REPORT"
    )

    lines.append(
        "=" * 28
    )

    lines.append(
        f"Risk: {risk}"
    )

    lines.append(
        f"Status: {headline}"
    )

    lines.append(
        ""
    )

    if summary:

        lines.append(
            "SUMMARY"
        )

        lines.append(
            summary
        )

        lines.append(
            ""
        )

    if reasons:

        lines.append(
            "WHY"
        )

        for reason in reasons:

            lines.append(
                f"- {reason}"
            )

        lines.append(
            ""
        )

    if dangerous_actions:

        lines.append(
            "DANGEROUS ACTIONS"
        )

        for action in dangerous_actions:

            lines.append(
                f"- {redact_sensitive_text(action)}"
            )

        lines.append(
            ""
        )

    if categories:

        lines.append(
            "POSSIBLE SCAM CATEGORIES"
        )

        for category in categories:

            lines.append(
                f"- {category}"
            )

        lines.append(
            ""
        )

    if actions:

        lines.append(
            "WHAT TO DO"
        )

        for action in actions:

            lines.append(
                f"- {redact_sensitive_text(action)}"
            )

        lines.append(
            ""
        )

    lines.append(
        "IMPORTANT"
    )

    lines.append(
        RISK_INSTRUCTIONS[risk]
    )

    lines.append(
        ""
    )

    lines.append(
        "ElderShield is a safety aid, not a guarantee."
    )

    return "\n".join(
        lines
    )


# ============================================================
# MARKDOWN FORMAT
# ============================================================

def report_to_markdown(
    report: dict[str, Any],
) -> str:
    """
    Convert a report into Markdown.
    """

    if not isinstance(
        report,
        dict,
    ):

        return "# ElderShield Report\n\nNo report available."

    risk = normalize_risk(
        report.get(
            "risk",
            "UNKNOWN",
        )
    )

    headline = str(
        report.get(
            "headline",
            RISK_HEADLINES[risk],
        )
    )

    summary = str(
        report.get(
            "summary",
            "",
        )
    )

    reasons = unique_strings(
        report.get(
            "reasons",
            [],
        )
    )

    actions = unique_strings(
        report.get(
            "recommended_actions",
            [],
        )
    )

    lines: list[str] = []

    lines.append(
        "# ElderShield Safety Report"
    )

    lines.append(
        ""
    )

    lines.append(
        f"## Risk: {risk}"
    )

    lines.append(
        ""
    )

    lines.append(
        f"**{headline}**"
    )

    lines.append(
        ""
    )

    if summary:

        lines.append(
            "### Summary"
        )

        lines.append(
            redact_sensitive_text(
                summary
            )
        )

        lines.append(
            ""
        )

    if reasons:

        lines.append(
            "### Why ElderShield is warning you"
        )

        for reason in reasons:

            lines.append(
                f"- {redact_sensitive_text(reason)}"
            )

        lines.append(
            ""
        )

    if actions:

        lines.append(
            "### What you should do"
        )

        for action in actions:

            lines.append(
                f"- {redact_sensitive_text(action)}"
            )

        lines.append(
            ""
        )

    lines.append(
        "### Important"
    )

    lines.append(
        RISK_INSTRUCTIONS[risk]
    )

    lines.append(
        ""
    )

    lines.append(
        "> ElderShield is a safety aid, not a guarantee."
    )

    return "\n".join(
        lines
    )
