"""
Tests for ElderShield privacy-conscious logging utilities.
"""

from modules.logging_utils import (
    redact_for_log,
    log_event,
)


# ============================================================
# REDACTION
# ============================================================

def test_otp_is_redacted_from_logs():
    text = "OTP 123456"

    result = redact_for_log(
        text
    )

    assert "123456" not in result


def test_upi_pin_is_redacted_from_logs():
    text = "UPI PIN: 4321"

    result = redact_for_log(
        text
    )

    assert "4321" not in result


def test_atm_pin_is_redacted_from_logs():
    text = "ATM PIN: 5678"

    result = redact_for_log(
        text
    )

    assert "5678" not in result


def test_cvv_is_redacted_from_logs():
    text = "CVV: 123"

    result = redact_for_log(
        text
    )

    assert "123" not in result


def test_password_is_redacted_from_logs():
    text = "password=SuperSecret123"

    result = redact_for_log(
        text
    )

    assert "SuperSecret123" not in result


def test_api_key_is_redacted_from_logs():
    text = (
        "GEMINI_API_KEY=AIzaSyExampleSecretKey123"
    )

    result = redact_for_log(
        text
    )

    assert "AIzaSyExampleSecretKey123" not in result


def test_normal_log_text_is_preserved():
    text = (
        "ElderShield analysis completed successfully."
    )

    result = redact_for_log(
        text
    )

    assert "analysis completed" in result


# ============================================================
# LOG EVENT
# ============================================================

def test_log_event_returns_safe_value():
    result = log_event(
        "analysis_completed",
        {
            "risk": "HIGH",
            "channel": "MESSAGE",
        },
    )

    assert result is not None


def test_log_event_does_not_return_raw_credentials():
    result = log_event(
        "analysis_completed",
        {
            "risk": "CRITICAL",
            "message": "OTP is 123456",
            "password": "SuperSecret123",
        },
    )

    serialized = str(
        result
    )

    assert "123456" not in serialized
    assert "SuperSecret123" not in serialized


def test_log_event_does_not_store_raw_message():
    result = log_event(
        "analysis_completed",
        {
            "message": (
                "My bank asked me for OTP 123456."
            )
        },
    )

    serialized = str(
        result
    )

    assert "My bank asked me for OTP 123456." not in serialized


def test_log_event_handles_empty_metadata():
    result = log_event(
        "startup",
        {},
    )

    assert result is not None
