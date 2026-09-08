"""
Tests for ElderShield notification helpers.
"""

from modules.notifications import (
    normalize_risk,
    create_notification,
    notification_text,
    critical_alert,
    call_notification,
)


def test_normalize_risk():
    assert normalize_risk("critical") == "CRITICAL"
    assert normalize_risk("HIGH") == "HIGH"
    assert normalize_risk("caution") == "CAUTION"
    assert normalize_risk("safe") == "SAFE"


def test_unknown_risk_is_unknown():
    assert normalize_risk("invalid") == "UNKNOWN"


def test_critical_notification():
    result = create_notification(
        {
            "risk": "CRITICAL",
            "summary": "OTP request detected.",
            "reasons": ["Credential request detected."],
            "actions": ["Do not share the OTP."],
        }
    )

    assert result["risk"] == "CRITICAL"
    assert result["requires_attention"] is True
    assert result["raw_evidence_included"] is False


def test_high_notification():
    result = create_notification(
        {
            "risk": "HIGH",
            "summary": "Suspicious payment request.",
            "reasons": ["Urgency detected."],
            "actions": ["Verify independently."],
        }
    )

    assert result["risk"] == "HIGH"
    assert result["requires_attention"] is True


def test_caution_notification():
    result = create_notification(
        {
            "risk": "CAUTION",
            "summary": "Unknown caller.",
        }
    )

    assert result["risk"] == "CAUTION"
    assert result["requires_attention"] is True


def test_safe_notification():
    result = create_notification(
        {
            "risk": "SAFE",
            "summary": "Normal message.",
        }
    )

    assert result["risk"] == "SAFE"
    assert result["requires_attention"] is False


def test_unknown_notification():
    result = create_notification(
        {
            "risk": "UNKNOWN",
        }
    )

    assert result["risk"] == "UNKNOWN"
    assert result["requires_attention"] is False


def test_notification_text_is_short_string():
    text = notification_text(
        {
            "risk": "HIGH",
            "summary": "Suspicious request.",
        }
    )

    assert isinstance(text, str)
    assert len(text) > 0


def test_critical_alert_only_for_critical():
    alert = critical_alert(
        {
            "risk": "CRITICAL",
        }
    )

    assert "STOP" in alert
    assert len(alert) > 0


def test_no_critical_alert_for_high():
    alert = critical_alert(
        {
            "risk": "HIGH",
        }
    )

    assert alert == ""


def test_call_notification_critical():
    result = call_notification(
        "CRITICAL"
    )

    assert result["risk"] == "CRITICAL"
    assert len(result["title"]) > 0
    assert len(result["message"]) > 0


def test_call_notification_high():
    result = call_notification(
        "HIGH"
    )

    assert result["risk"] == "HIGH"


def test_call_notification_caution():
    result = call_notification(
        "CAUTION"
    )

    assert result["risk"] == "CAUTION"


def test_call_notification_safe():
    result = call_notification(
        "SAFE"
    )

    assert result["risk"] == "SAFE"


def test_call_notification_unknown():
    result = call_notification(
        "something-invalid"
    )

    assert result["risk"] == "UNKNOWN"


def test_notification_does_not_include_raw_evidence():
    result = create_notification(
        {
            "risk": "CRITICAL",
            "message": "My OTP is 123456",
            "summary": "OTP request.",
        }
    )

    serialized = str(result)

    assert "123456" not in serialized
    assert result["raw_evidence_included"] is False
