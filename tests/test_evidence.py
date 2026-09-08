"""
Tests for ElderShield evidence correlation.
"""

from modules.evidence import (
    EvidenceItem,
    EvidenceReport,
)


def test_evidence_item_creation():
    item = EvidenceItem(
        source="TEXT_RULES",
        signal="credential_request",
        strength="STRONG",
        description="OTP request detected.",
    )

    assert item.source == "TEXT_RULES"
    assert item.signal == "credential_request"
    assert item.strength == "STRONG"


def test_evidence_report_starts_empty():
    report = EvidenceReport()

    assert report.independent_sources == 0
    assert report.strong_signals == 0
    assert report.critical_signals == 0


def test_add_text_rule_evidence():
    report = EvidenceReport()

    report.add_text_rules(
        {
            "risk": "HIGH",
            "signal_groups": [
                "urgency",
                "credential_request",
            ],
            "dangerous_actions": [
                "OTP",
            ],
            "reasons": [
                "OTP request detected.",
            ],
        }
    )

    assert report.independent_sources >= 1
    assert report.strong_signals >= 1


def test_critical_action_creates_critical_evidence():
    report = EvidenceReport()

    report.add_text_rules(
        {
            "risk": "CRITICAL",
            "signal_groups": [
                "credential_request",
            ],
            "dangerous_actions": [
                "UPI PIN",
            ],
            "reasons": [
                "UPI PIN requested.",
            ],
        }
    )

    assert report.critical_signals >= 1


def test_add_url_evidence():
    report = EvidenceReport()

    report.add_url(
        {
            "risk": "HIGH",
            "domain": "example.com",
            "reasons": [
                "Suspicious URL detected.",
            ],
        }
    )

    assert report.independent_sources >= 1
    assert report.strong_signals >= 1


def test_add_brand_evidence():
    report = EvidenceReport()

    report.add_brand(
        {
            "status": "MISMATCH",
            "risk": "HIGH",
            "organization": "SBI",
            "reasons": [
                "Claimed organization does not match domain."
            ],
        }
    )

    assert report.independent_sources >= 1


def test_add_ai_evidence():
    report = EvidenceReport()

    report.add_ai(
        {
            "risk": "HIGH",
            "summary": "Suspicious financial request.",
            "reasons": [
                "Urgency and payment request detected."
            ],
            "dangerous_actions": [
                "PAYMENT",
            ],
        }
    )

    assert report.independent_sources >= 1


def test_multiple_sources_are_counted():
    report = EvidenceReport()

    report.add_text_rules(
        {
            "risk": "HIGH",
            "signal_groups": [
                "urgency",
            ],
            "dangerous_actions": [],
            "reasons": [
                "Urgency detected."
            ],
        }
    )

    report.add_url(
        {
            "risk": "HIGH",
            "domain": "example.com",
            "reasons": [
                "Suspicious URL."
            ],
        }
    )

    report.add_brand(
        {
            "status": "MISMATCH",
            "risk": "HIGH",
            "organization": "SBI",
            "reasons": [
                "Domain mismatch."
            ],
        }
    )

    assert report.independent_sources >= 3


def test_evidence_is_not_proof():
    report = EvidenceReport()

    report.add_text_rules(
        {
            "risk": "HIGH",
            "signal_groups": [
                "urgency",
            ],
            "dangerous_actions": [],
            "reasons": [
                "Urgency detected."
            ],
        }
    )

    result = report.to_dict()

    assert result.get(
        "is_proof",
        False,
    ) is False


def test_report_to_dict_contains_counts():
    report = EvidenceReport()

    report.add_text_rules(
        {
            "risk": "CRITICAL",
            "signal_groups": [
                "credential_request",
            ],
            "dangerous_actions": [
                "OTP",
            ],
            "reasons": [
                "OTP requested."
            ],
        }
    )

    result = report.to_dict()

    assert "independent_sources" in result
    assert "strong_signals" in result
    assert "critical_signals" in result


def test_evidence_summary_is_safe():
    report = EvidenceReport()

    report.add_text_rules(
        {
            "risk": "CRITICAL",
            "signal_groups": [
                "credential_request",
            ],
            "dangerous_actions": [
                "OTP",
            ],
            "reasons": [
                "OTP requested."
            ],
        }
    )

    summary = report.summary()

    assert isinstance(
        summary,
        str,
    )

    # The evidence summary should describe the signal,
    # not expose a real credential.
    assert "OTP" in summary
