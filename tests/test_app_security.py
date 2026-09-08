"""
Tests for ElderShield application security helpers.
"""

from modules.app_security import (
    redact_sensitive,
    safe_filename,
    validate_text_length,
    security_status,
)


# ============================================================
# SENSITIVE DATA REDACTION
# ============================================================

def test_otp_is_redacted():
    text = "Your OTP is 123456."

    result = redact_sensitive(
        text
    )

    assert "123456" not in result


def test_upi_pin_is_redacted():
    text = "UPI PIN: 4321"

    result = redact_sensitive(
        text
    )

    assert "4321" not in result


def test_cvv_is_redacted():
    text = "CVV: 123"

    result = redact_sensitive(
        text
    )

    assert "123" not in result


def test_api_key_is_redacted():
    text = (
        "GEMINI_API_KEY=AIzaSyExampleSecretKey123456"
    )

    result = redact_sensitive(
        text
    )

    assert "AIzaSyExampleSecretKey123456" not in result


def test_password_is_redacted():
    text = "password=SuperSecret123"

    result = redact_sensitive(
        text
    )

    assert "SuperSecret123" not in result


def test_normal_text_is_preserved():
    text = (
        "Please verify the request through an official channel."
    )

    result = redact_sensitive(
        text
    )

    assert "official channel" in result


# ============================================================
# SAFE FILENAMES
# ============================================================

def test_safe_filename_removes_path_traversal():
    result = safe_filename(
        "../../secret.txt"
    )

    assert ".." not in result
    assert "/" not in result
    assert "\\" not in result


def test_safe_filename_removes_unsafe_characters():
    result = safe_filename(
        "my report<>:\"/\\|?*.txt"
    )

    assert "/" not in result
    assert "\\" not in result
    assert "<" not in result
    assert ">" not in result
    assert ":" not in result
    assert "*" not in result
    assert "?" not in result


def test_empty_filename_gets_safe_value():
    result = safe_filename("")

    assert isinstance(
        result,
        str,
    )

    assert len(result) > 0


# ============================================================
# TEXT LENGTH
# ============================================================

def test_short_text_is_valid():
    result = validate_text_length(
        "Hello ElderShield"
    )

    assert result["valid"] is True


def test_long_text_is_rejected():
    result = validate_text_length(
        "A" * 25_000
    )

    assert result["valid"] is False


def test_empty_text_is_invalid():
    result = validate_text_length(
        ""
    )

    assert result["valid"] is False


# ============================================================
# SECURITY STATUS
# ============================================================

def test_security_status_returns_dictionary():
    result = security_status()

    assert isinstance(
        result,
        dict,
    )


def test_security_status_does_not_expose_secret():
    result = security_status()

    serialized = str(result).lower()

    assert "api_key" not in serialized
    assert "secret" not in serialized
    assert "password" not in serialized


def test_security_status_contains_security_information():
    result = security_status()

    assert len(result) > 0
