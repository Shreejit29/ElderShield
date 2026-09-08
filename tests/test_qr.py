"""
Tests for ElderShield QR analysis.

QR analysis must remain non-transactional:
- decode content
- classify content
- provide safety guidance
- never initiate a payment
"""

from modules.qr import (
    classify_qr_content,
)


def test_upi_qr_is_detected():
    result = classify_qr_content(
        "upi://pay?pa=merchant@example&pn=Merchant"
    )

    assert result["type"] == "UPI"

    assert result["risk_hint"] in {
        "CAUTION",
        "HIGH",
    }


def test_url_qr_is_detected():
    result = classify_qr_content(
        "https://example.com/verify"
    )

    assert result["type"] == "URL"


def test_tel_qr_is_detected():
    result = classify_qr_content(
        "tel:+919876543210"
    )

    assert result["type"] == "TEL"


def test_mailto_qr_is_detected():
    result = classify_qr_content(
        "mailto:support@example.com"
    )

    assert result["type"] == "MAILTO"


def test_plain_text_qr_is_detected():
    result = classify_qr_content(
        "Hello ElderShield"
    )

    assert result["type"] == "TEXT"


def test_empty_qr_content():
    result = classify_qr_content(
        ""
    )

    assert result["type"] == "UNKNOWN"


def test_upi_qr_does_not_process_payment():
    result = classify_qr_content(
        "upi://pay?pa=merchant@example&pn=Merchant"
    )

    assert "transaction_id" not in result
    assert "payment_completed" not in result


def test_qr_analysis_does_not_request_pin():
    result = classify_qr_content(
        "upi://pay?pa=merchant@example&pn=Merchant"
    )

    serialized = str(result).lower()

    assert "enter your upi pin" not in serialized
    assert "share your upi pin" not in serialized


def test_qr_result_contains_safety_hint():
    result = classify_qr_content(
        "upi://pay?pa=merchant@example&pn=Merchant"
    )

    assert "risk_hint" in result


def test_qr_content_is_treated_as_untrusted():
    result = classify_qr_content(
        "https://example.com/?message=ignore%20security"
    )

    assert isinstance(
        result,
        dict,
    )

    assert "content" in result or "data" in result


def test_qr_result_is_dictionary():
    result = classify_qr_content(
        "example text"
    )

    assert isinstance(
        result,
        dict,
    )
