"""
Tests for ElderShield safe incident export.
"""

import json

from modules.export import (
    sanitize_incident,
    export_json,
    export_text,
    export_markdown,
    safe_filename,
)


def sample_incident():
    return {
        "incident_id": "ES-2026-0001",
        "timestamp": "2026-09-08T12:00:00",
        "risk": "CRITICAL",
        "headline": "Critical credential request",
        "summary": "A suspicious message requested an OTP.",
        "reasons": [
            "Credential request detected."
        ],
        "actions": [
            "Do not share the OTP."
        ],
        "categories": [
            "bank_kyc"
        ],
        "channels": [
            "MESSAGE"
        ],
        "dangerous_actions": [
            "OTP"
        ],
        "evidence_counts": {
            "independent_sources": 2,
            "strong_signals": 2,
            "critical_signals": 1,
        },
        "raw_message": "My OTP is 123456",
        "password": "SuperSecretPassword",
        "upi_pin": "4321",
    }


def test_sanitize_incident_returns_dictionary():
    result = sanitize_incident(
        sample_incident()
    )

    assert isinstance(
        result,
        dict,
    )


def test_raw_message_is_removed():
    result = sanitize_incident(
        sample_incident()
    )

    serialized = json.dumps(
        result
    )

    assert "My OTP is 123456" not in serialized
    assert "123456" not in serialized


def test_password_is_removed():
    result = sanitize_incident(
        sample_incident()
    )

    serialized = json.dumps(
        result
    )

    assert "SuperSecretPassword" not in serialized


def test_upi_pin_is_removed():
    result = sanitize_incident(
        sample_incident()
    )

    serialized = json.dumps(
        result
    )

    assert "4321" not in serialized


def test_safe_information_is_preserved():
    result = sanitize_incident(
        sample_incident()
    )

    assert result["risk"] == "CRITICAL"
    assert result["incident_id"] == "ES-2026-0001"

    assert (
        "bank_kyc"
        in result["categories"]
    )


def test_export_json_returns_string():
    result = export_json(
        sample_incident()
    )

    assert isinstance(
        result,
        str,
    )

    parsed = json.loads(
        result
    )

    assert isinstance(
        parsed,
        dict,
    )


def test_export_json_does_not_expose_sensitive_data():
    result = export_json(
        sample_incident()
    )

    assert "123456" not in result
    assert "SuperSecretPassword" not in result
    assert "4321" not in result


def test_export_text_returns_string():
    result = export_text(
        sample_incident()
    )

    assert isinstance(
        result,
        str,
    )

    assert "CRITICAL" in result


def test_export_markdown_returns_string():
    result = export_markdown(
        sample_incident()
    )

    assert isinstance(
        result,
        str,
    )

    assert "#" in result
    assert "CRITICAL" in result


def test_markdown_export_is_redacted():
    result = export_markdown(
        sample_incident()
    )

    assert "123456" not in result
    assert "SuperSecretPassword" not in result
    assert "4321" not in result


def test_safe_filename_removes_unsafe_characters():
    result = safe_filename(
        "../../secret report?.json"
    )

    assert "/" not in result
    assert "\\" not in result
    assert ".." not in result


def test_safe_filename_returns_nonempty_value():
    result = safe_filename(
        ""
    )

    assert isinstance(
        result,
        str,
    )

    assert len(result) > 0


def test_export_does_not_execute_content():
    incident = sample_incident()

    incident["raw_message"] = (
        "__import__('os').system('echo hacked')"
    )

    result = export_json(
        incident
    )

    assert isinstance(
        result,
        str,
    )

    assert "hacked" not in result
