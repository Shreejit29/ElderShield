"""
ElderShield Evidence Correlation

Combines independent evidence sources into a compact,
explainable evidence record.

IMPORTANT:
- Evidence is not proof.
- Multiple independent signals can increase confidence.
- Missing evidence must not be treated as safe evidence.
- AI output is treated as one evidence source, not absolute truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ============================================================
# DATA MODEL
# ============================================================

@dataclass
class EvidenceItem:
    """
    One piece of evidence supporting an ElderShield decision.
    """

    source: str
    signal: str
    detail: str
    strength: str = "MEDIUM"


@dataclass
class EvidenceReport:
    """
    Correlated evidence collected from multiple sources.
    """

    items: list[EvidenceItem] = field(
        default_factory=list
    )

    sources: list[str] = field(
        default_factory=list
    )

    independent_source_count: int = 0

    strong_signal_count: int = 0

    critical_signal_count: int = 0


# ============================================================
# CONSTANTS
# ============================================================

VALID_STRENGTHS = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


CRITICAL_ACTIONS = {
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


# ============================================================
# HELPERS
# ============================================================

def _normalize_strength(
    strength: str,
) -> str:
    """
    Normalize evidence strength.
    """

    value = str(
        strength or "MEDIUM"
    ).strip().upper()

    if value not in VALID_STRENGTHS:

        return "MEDIUM"

    return value


def _add_item(
    report: EvidenceReport,
    source: str,
    signal: str,
    detail: str,
    strength: str = "MEDIUM",
) -> None:
    """
    Add one evidence item while avoiding exact duplicates.
    """

    source = str(
        source or "unknown"
    ).strip()

    signal = str(
        signal or "signal"
    ).strip()

    detail = str(
        detail or ""
    ).strip()

    if not detail:
        return

    strength = _normalize_strength(
        strength
    )

    for existing in report.items:

        if (
            existing.source == source
            and existing.signal == signal
            and existing.detail == detail
        ):

            return

    report.items.append(
        EvidenceItem(
            source=source,
            signal=signal,
            detail=detail,
            strength=strength,
        )
    )


# ============================================================
# TEXT EVIDENCE
# ============================================================

def add_text_evidence(
    report: EvidenceReport,
    text_rules: dict[str, Any] | None,
) -> None:
    """
    Add evidence from deterministic text analysis.
    """

    if not isinstance(
        text_rules,
        dict,
    ):
        return

    signal_groups = text_rules.get(
        "signal_groups",
        {},
    )

    if isinstance(
        signal_groups,
        dict,
    ):

        for group, matches in signal_groups.items():

            if isinstance(
                matches,
                list,
            ) and matches:

                detail = (
                    f"Detected {group.replace('_', ' ')} "
                    f"signals: {', '.join(str(x) for x in matches[:5])}."
                )

            else:

                detail = (
                    f"Detected {group.replace('_', ' ')} signals."
                )

            strength = "MEDIUM"

            if group in {
                "credential_request",
                "remote_access",
                "financial_request",
                "digital_arrest",
            }:

                strength = "HIGH"

            _add_item(
                report,
                "text_rules",
                group,
                detail,
                strength,
            )

    dangerous_actions = text_rules.get(
        "dangerous_actions",
        [],
    )

    if isinstance(
        dangerous_actions,
        list,
    ):

        for action in dangerous_actions:

            action_name = str(
                action
            ).strip()

            if not action_name:
                continue

            strength = (
                "CRITICAL"
                if action_name in CRITICAL_ACTIONS
                else "HIGH"
            )

            _add_item(
                report,
                "text_rules",
                "dangerous_action",
                f"Detected dangerous action: {action_name}.",
                strength,
            )


# ============================================================
# URL EVIDENCE
# ============================================================

def add_url_evidence(
    report: EvidenceReport,
    url_analysis: dict[str, Any] | None,
) -> None:
    """
    Add evidence from URL structural analysis.
    """

    if not isinstance(
        url_analysis,
        dict,
    ):
        return

    risk = str(
        url_analysis.get(
            "risk",
            "",
        )
    ).upper()

    reasons = url_analysis.get(
        "reasons",
        [],
    )

    if isinstance(
        reasons,
        list,
    ):

        for reason in reasons[:10]:

            strength = "MEDIUM"

            if risk in {
                "HIGH RISK",
                "CRITICAL",
            }:

                strength = "HIGH"

            _add_item(
                report,
                "url_analyzer",
                "suspicious_url",
                str(reason),
                strength,
            )

    domain = str(
        url_analysis.get(
            "domain",
            "",
        )
    ).strip()

    if domain:

        _add_item(
            report,
            "url_analyzer",
            "domain",
            f"URL domain observed: {domain}.",
            "LOW",
        )


# ============================================================
# BRAND EVIDENCE
# ============================================================

def add_brand_evidence(
    report: EvidenceReport,
    brand_analysis: dict[str, Any] | None,
) -> None:
    """
    Add organization/domain mismatch evidence.
    """

    if not isinstance(
        brand_analysis,
        dict,
    ):
        return

    checks = brand_analysis.get(
        "checks",
        [],
    )

    if not isinstance(
        checks,
        list,
    ):
        return

    for check in checks:

        if not isinstance(
            check,
            dict,
        ):
            continue

        status = str(
            check.get(
                "status",
                "",
            )
        ).upper()

        organization = str(
            check.get(
                "organization",
                "",
            )
        )

        actual_domain = str(
            check.get(
                "actual_domain",
                "",
            )
        )

        official_domain = str(
            check.get(
                "official_domain",
                "",
            )
        )

        if status == "MISMATCH":

            _add_item(
                report,
                "brand_check",
                "domain_mismatch",
                (
                    f"{organization} was claimed, but the supplied "
                    f"domain '{actual_domain}' does not match the "
                    f"recorded official domain '{official_domain}'."
                ),
                "HIGH",
            )

        elif status == "MATCH":

            _add_item(
                report,
                "brand_check",
                "domain_match",
                (
                    f"The supplied domain matches the recorded "
                    f"official domain for {organization}."
                ),
                "LOW",
            )


# ============================================================
# QR EVIDENCE
# ============================================================

def add_qr_evidence(
    report: EvidenceReport,
    qr_analysis: dict[str, Any] | None,
) -> None:
    """
    Add QR decoding/classification evidence.
    """

    if not isinstance(
        qr_analysis,
        dict,
    ):
        return

    if not qr_analysis.get(
        "found",
        False,
    ):
        return

    results = qr_analysis.get(
        "results",
        [],
    )

    if not isinstance(
        results,
        list,
    ):
        return

    for result in results:

        if not isinstance(
            result,
            dict,
        ):
            continue

        qr_type = str(
            result.get(
                "type",
                "UNKNOWN",
            )
        )

        risk_hint = str(
            result.get(
                "risk_hint",
                "UNKNOWN",
            )
        ).upper()

        summary = str(
            result.get(
                "summary",
                "",
            )
        )

        strength = "MEDIUM"

        if risk_hint == "CAUTION":
            strength = "MEDIUM"

        elif risk_hint in {
            "HIGH RISK",
            "CRITICAL",
        }:
            strength = "HIGH"

        _add_item(
            report,
            "qr",
            "qr_payload",
            (
                f"QR payload classified as {qr_type}. "
                f"{summary}"
            ),
            strength,
        )


# ============================================================
# AI EVIDENCE
# ============================================================

def add_ai_evidence(
    report: EvidenceReport,
    ai_analysis: dict[str, Any] | None,
    source: str = "gemini",
) -> None:
    """
    Add AI-derived evidence.

    AI output is deliberately labelled as AI evidence so the
    final system can distinguish it from deterministic signals.
    """

    if not isinstance(
        ai_analysis,
        dict,
    ):
        return

    risk = str(
        ai_analysis.get(
            "risk",
            "UNKNOWN",
        )
    ).upper()

    summary = str(
        ai_analysis.get(
            "summary",
            "",
        )
    ).strip()

    if summary:

        strength = "MEDIUM"

        if risk == "CRITICAL":
            strength = "CRITICAL"

        elif risk == "HIGH RISK":
            strength = "HIGH"

        elif risk == "CAUTION":
            strength = "MEDIUM"

        _add_item(
            report,
            source,
            "ai_summary",
            summary,
            strength,
        )

    reasons = ai_analysis.get(
        "reasons",
        [],
    )

    if isinstance(
        reasons,
        list,
    ):

        for reason in reasons[:8]:

            _add_item(
                report,
                source,
                "ai_reason",
                str(reason),
                "MEDIUM",
            )

    dangerous_actions = ai_analysis.get(
        "dangerous_actions",
        [],
    )

    if isinstance(
        dangerous_actions,
        list,
    ):

        for action in dangerous_actions:

            action_name = str(
                action
            ).strip()

            if not action_name:
                continue

            strength = (
                "CRITICAL"
                if action_name.upper()
                in CRITICAL_ACTIONS
                else "HIGH"
            )

            _add_item(
                report,
                source,
                "ai_dangerous_action",
                (
                    f"AI detected potentially dangerous action: "
                    f"{action_name}."
                ),
                strength,
            )


# ============================================================
# REPORT FINALIZATION
# ============================================================

def finalize_report(
    report: EvidenceReport,
) -> EvidenceReport:
    """
    Calculate evidence statistics.
    """

    sources = []

    for item in report.items:

        if item.source not in sources:

            sources.append(
                item.source
            )

    report.sources = sources

    report.independent_source_count = len(
        sources
    )

    report.strong_signal_count = sum(
        1
        for item in report.items
        if item.strength in {
            "HIGH",
            "CRITICAL",
        }
    )

    report.critical_signal_count = sum(
        1
        for item in report.items
        if item.strength == "CRITICAL"
    )

    return report


# ============================================================
# MAIN CORRELATION FUNCTION
# ============================================================

def correlate_evidence(
    *,
    text_rules: dict[str, Any] | None = None,
    url_analysis: dict[str, Any] | None = None,
    brand_analysis: dict[str, Any] | None = None,
    qr_analysis: dict[str, Any] | None = None,
    ai_analysis: dict[str, Any] | None = None,
    ai_source: str = "gemini",
) -> EvidenceReport:
    """
    Combine evidence from all available sources.
    """

    report = EvidenceReport()

    add_text_evidence(
        report,
        text_rules,
    )

    add_url_evidence(
        report,
        url_analysis,
    )

    add_brand_evidence(
        report,
        brand_analysis,
    )

    add_qr_evidence(
        report,
        qr_analysis,
    )

    add_ai_evidence(
        report,
        ai_analysis,
        source=ai_source,
    )

    return finalize_report(
        report
    )


# ============================================================
# SERIALIZATION
# ============================================================

def evidence_to_dict(
    report: EvidenceReport,
) -> dict[str, Any]:
    """
    Convert an EvidenceReport to a JSON-friendly dictionary.
    """

    return {
        "items": [
            {
                "source": item.source,
                "signal": item.signal,
                "detail": item.detail,
                "strength": item.strength,
            }
            for item in report.items
        ],
        "sources": list(
            report.sources
        ),
        "independent_source_count": (
            report.independent_source_count
        ),
        "strong_signal_count": (
            report.strong_signal_count
        ),
        "critical_signal_count": (
            report.critical_signal_count
        ),
    }
