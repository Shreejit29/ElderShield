"""
Tests for ElderShield email safety checks.

These tests are fully offline. ElderShield does not access
the user's mailbox through this module.
"""

from modules.email_check import check_email


def test_normal_email_is_not_critical():
    result = check_email(
        sender="friend@example.com",
        subject="Hello",
        body="Let's meet tomorrow for lunch.",
    )

    assert result["risk"] != "CRITICAL"


def test_invalid_sender_is_rejected():
    result = check_email(
        sender="not-an-email",
        subject="Hello",
        body="Test message",
    )

    assert result["valid"] is False


def test_otp_request_is_critical():
    result = check_email(
        sender="support@example.com",
        subject="Account verification",
        body="Share your OTP immediately to verify your account.",
    )

    assert result["risk"] == "CRITICAL"

    assert "OTP" in result["dangerous_actions"]


def test_password_request_is_critical():
    result = check_email(
        sender="security@example.com",
        subject="Account verification",
        body="Send us your banking password for verification.",
    )

    assert result["risk"] == "CRITICAL"

    assert "PASSWORD" in result["dangerous_actions"]


def test_upi_pin_request_is_critical():
    result = check_email(
        sender="refund@example.com",
        subject="Refund",
        body="Provide your UPI PIN to receive your refund.",
    )

    assert result["risk"] == "CRITICAL"


def test_remote_access_request_is_critical():
    result = check_email(
        sender="support@example.com",
        subject="Technical support",
        body="Install AnyDesk and give us remote access.",
    )

    assert result["risk"] == "CRITICAL"


def test_payment_request_is_detected():
    result = check_email(
        sender="offers@example.com",
        subject="Payment required",
        body="Pay Rs 999 to complete your registration.",
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_digital_arrest_email_is_high_risk():
    result = check_email(
        sender="police@example.com",
        subject="Legal notice",
        body=(
            "Your Aadhaar is linked to a criminal case. "
            "You must cooperate immediately."
        ),
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_job_scam_email_is_detected():
    result = check_email(
        sender="jobs@example.com",
        subject="Job offer",
        body=(
            "Congratulations. You have been selected. "
            "Pay a registration fee to start your job."
        ),
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_investment_scam_email_is_detected():
    result = check_email(
        sender="invest@example.com",
        subject="Guaranteed returns",
        body=(
            "Invest today and receive guaranteed 50 percent returns."
        ),
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_suspicious_url_is_analyzed():
    result = check_email(
        sender="security@example.com",
        subject="Verify account",
        body=(
            "Click https://example.com/verify-account-login "
            "to continue."
        ),
    )

    assert len(
        result.get(
            "urls",
            [],
        )
    ) > 0


def test_free_email_provider_is_not_automatically_scam():
    result = check_email(
        sender="person@gmail.com",
        subject="Hello",
        body="Just checking in.",
    )

    assert result["risk"] != "CRITICAL"


def test_sender_and_content_are_combined():
    result = check_email(
        sender="bank-security@example.com",
        subject="Account blocked",
        body=(
            "Your account will be blocked today. "
            "Share your OTP and password immediately."
        ),
    )

    assert result["risk"] == "CRITICAL"

    assert "OTP" in result["dangerous_actions"]
    assert "PASSWORD" in result["dangerous_actions"]


def test_email_result_contains_actions():
    result = check_email(
        sender="support@example.com",
        subject="Urgent",
        body="Your account needs immediate verification.",
    )

    assert len(
        result.get(
            "actions",
            [],
        )
    ) > 0
