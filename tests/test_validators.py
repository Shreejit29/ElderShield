"""
Tests for ElderShield input validators.
"""

from modules.validators import (
    validate_text,
    validate_url,
    validate_phone,
    safe_display_text,
)


# ============================================================
# TEXT
# ============================================================

def test_valid_text_is_accepted():
    result = validate_text(
        "Your electricity bill is ready."
    )

    assert result["valid"] is True


def test_empty_text_is_rejected():
    result = validate_text("")

    assert result["valid"] is False


def test_whitespace_text_is_rejected():
    result = validate_text("   ")

    assert result["valid"] is False


def test_excessively_long_text_is_rejected():
    result = validate_text(
        "A" * 25_000
    )

    assert result["valid"] is False


# ============================================================
# URL
# ============================================================

def test_valid_https_url():
    result = validate_url(
        "https://example.com"
    )

    assert result["valid"] is True


def test_valid_http_url():
    result = validate_url(
        "http://example.com"
    )

    assert result["valid"] is True


def test_empty_url_is_rejected():
    result = validate_url("")

    assert result["valid"] is False


def test_javascript_url_is_rejected():
    result = validate_url(
        "javascript:alert(1)"
    )

    assert result["valid"] is False


def test_file_url_is_rejected():
    result = validate_url(
        "file:///etc/passwd"
    )

    assert result["valid"] is False


def test_malformed_url_is_rejected():
    result = validate_url(
        "not a valid url"
    )

    assert result["valid"] is False


# ============================================================
# PHONE
# ============================================================

def test_valid_indian_phone():
    result = validate_phone(
        "+919876543210"
    )

    assert result["valid"] is True


def test_valid_local_indian_phone():
    result = validate_phone(
        "9876543210"
    )

    assert result["valid"] is True


def test_invalid_phone_is_rejected():
    result = validate_phone(
        "12345"
    )

    assert result["valid"] is False


def test_phone_with_letters_is_rejected():
    result = validate_phone(
        "98765ABCDE0"
    )

    assert result["valid"] is False


# ============================================================
# SAFE DISPLAY
# ============================================================

def test_safe_display_text_returns_string():
    result = safe_display_text(
        "Hello ElderShield"
    )

    assert isinstance(
        result,
        str,
    )


def test_safe_display_text_handles_none():
    result = safe_display_text(
        None
    )

    assert isinstance(
        result,
        str,
    )


def test_safe_display_text_limits_extreme_length():
    result = safe_display_text(
        "A" * 50_000
    )

    assert len(result) <= 10_000
