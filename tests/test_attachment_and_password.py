"""
Tests for ElderShield attachment-related and credential-safety helpers.
"""

from modules.password_check import check_password_request
from modules.attachment_check import check_attachment


# ============================================================
# PASSWORD / CREDENTIAL REQUESTS
# ============================================================

def test_password_request_is_critical():
    result = check_password_request(
        "Please send your banking password for verification."
    )

    assert result["risk"] == "CRITICAL"


def test_otp_request_is_critical():
    result = check_password_request(
        "Tell me the OTP you received."
    )

    assert result["risk"] == "CRITICAL"


def test_upi_pin_request_is_critical():
    result = check_password_request(
        "Enter your UPI PIN to receive the refund."
    )

    assert result["risk"] == "CRITICAL"


def test_atm_pin_request_is_critical():
    result = check_password_request(
        "Share your ATM PIN to unblock the card."
    )

    assert result["risk"] == "CRITICAL"


def test_cvv_request_is_critical():
    result = check_password_request(
        "Give me the CVV printed on your card."
    )

    assert result["risk"] == "CRITICAL"


def test_normal_message_is_not_critical():
    result = check_password_request(
        "Please verify your account through the official website."
    )

    assert result["risk"] != "CRITICAL"


def test_password_checker_does_not_need_actual_password():
    result = check_password_request(
        "The password field is required."
    )

    # The module analyzes the request context only.
    assert "password_value" not in result
    assert "stored_password" not in result


# ============================================================
# ATTACHMENT + SOCIAL ENGINEERING
# ============================================================

def test_bank_update_apk_is_high_risk():
    result = check_attachment(
        filename="bank_account_update.apk",
        content_type=(
            "application/vnd.android.package-archive"
        ),
        data=b"fake apk",
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_remote_access_executable_is_high_risk():
    result = check_attachment(
        filename="AnyDesk_Update.exe",
        content_type="application/octet-stream",
        data=b"MZ",
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_double_extension_executable_is_flagged():
    result = check_attachment(
        filename="invoice.pdf.exe",
        content_type="application/octet-stream",
        data=b"MZ",
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_attachment_checker_never_executes_file():
    result = check_attachment(
        filename="suspicious.exe",
        content_type="application/octet-stream",
        data=b"MZ",
    )

    assert result.get(
        "executed",
        False,
    ) is False


def test_safe_pdf_remains_noncritical():
    result = check_attachment(
        filename="normal_document.pdf",
        content_type="application/pdf",
        data=b"%PDF-1.7\n",
    )

    assert result["risk"] != "CRITICAL"
