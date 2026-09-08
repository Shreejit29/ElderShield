"""
Tests for ElderShield report generation and redaction.
"""

from modules.report import (
    normalize_risk,
    redact_sensitive_text,
    build_report,
    report_from_case,
    report_to_text,
    report_to_markdown,
)


# ============================================================
# RISK NORMALIZATION
# ============================================================

def test_normalize_known_risk():
    assert normalize_risk("critical") == "CRITICAL"
    assert normalize_risk("HIGH") == "HIGH"
    assert normalize_risk("caution") == "CAUTION"
    assert normalize_risk("safe") == "SAFE"


def test_unknown_risk_becomes_unknown():
    assert normalize_risk("something-else") == "UNKNOWN"


def test_empty_risk_becomes_unknown():
    assert normalize_risk("") == "UNKNOWN"


# ============================================================
# SENSITIVE DATA REDACTION
# ============================================================

def test_six_digit_otp_is_redacted():
    text = "Your OTP is 123456."

    redacted = redact_sensitive_text(text)

    assert "123456" not in redacted


def test_labeled_pin_is_redacted():
    text = "UPI PIN: 4321"

    redacted = redact_sensitive_text(text)

    assert "4321" not in redacted


def test_labeled_cvv_is_redacted():
    text = "CVV: 123"

    redacted = redact_sensitive_text(text)

    assert "123" not in redacted


def test_normal_text_is_preserved():
    text = "Please verify the request through the official website."

    redacted = redact_sensitive_text(text)

    assert "official website" in redacted


# ============================================================
# REPORT CREATION
# ============================================================

def test_build_critical_report():
    report = build_report(
        risk="CRITICAL",
        summary="A suspicious message requests an OTP.",
        reasons=[
            "Credential request detected."
        ],
        actions=[
            "Do not share the OTP."
        ],
        categories=[
            "bank_kyc"
        ],
        dangerous_actions=[
            "OTP"
        ],
        channels=[
            "MESSAGE"
        ],
    )

    assert report["risk"] == "CRITICAL"
    assert "OTP" in report["dangerous_actions"]
    assert "MESSAGE" in report["channels"]


def test_report_from_case():
    case = {
        "risk": "HIGH",
        "summary": "Suspicious bank verification request.",
        "reasons": [
            "Urgency detected."
        ],
        "actions": [
            "Verify through the official bank channel."
        ],
        "categories": [
            "bank_kyc"
        ],
        "dangerous_actions": [],
        "channels": [
            "MESSAGE"
        ],
    }

    report = report_from_case(case)

    assert report["risk"] == "HIGH"
    assert len(report["actions"]) > 0


def test_report_does_not_store_raw_credentials():
    case = {
        "risk": "CRITICAL",
        "summary": "OTP 123456 requested.",
        "reasons": [
            "OTP: 123456"
        ],
        "actions": [
            "Do not share the OTP."
        ],
        "dangerous_actions": [
            "OTP"
        ],
        "channels": [
            "MESSAGE"
        ],
    }

    report = report_from_case(case)

    text = report_to_text(report)

    assert "123456" not in text


# ============================================================
# TEXT EXPORT
# ============================================================

def test_report_to_text_returns_string():
    report = build_report(
        risk="CAUTION",
        summary="Use caution.",
        reasons=["Suspicious request."],
        actions=["Verify independently."],
        categories=[],
        dangerous_actions=[],
        channels=["MESSAGE"],
    )

    text = report_to_text(report)

    assert isinstance(text, str)
    assert len(text) > 0


# ============================================================
# MARKDOWN EXPORT
# ============================================================

def test_report_to_markdown_returns_markdown():
    report = build_report(
        risk="HIGH",
        summary="High-risk request detected.",
        reasons=["Urgency detected."],
        actions=["Do not proceed."],
        categories=["job"],
        dangerous_actions=[],
        channels=["MESSAGE"],
    )

    markdown = report_to_markdown(report)

    assert isinstance(markdown, str)
    assert "#" in markdown
    assert "HIGH" in markdown
