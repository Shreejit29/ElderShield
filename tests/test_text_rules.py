"""
Tests for ElderShield deterministic text rules.
"""

from modules.text_rules import analyze_text_rules


def test_otp_request_is_critical():
    result = analyze_text_rules(
        "Your bank account will be blocked. Share the OTP immediately."
    )

    assert result["risk"] == "CRITICAL"
    assert "OTP" in result["dangerous_actions"]


def test_upi_pin_request_is_critical():
    result = analyze_text_rules(
        "Send me your UPI PIN to complete the refund."
    )

    assert result["risk"] == "CRITICAL"
    assert "UPI PIN" in result["dangerous_actions"]


def test_password_request_is_critical():
    result = analyze_text_rules(
        "Tell me your internet banking password so I can verify your account."
    )

    assert result["risk"] == "CRITICAL"
    assert "PASSWORD" in result["dangerous_actions"]


def test_remote_access_request_is_high_risk():
    result = analyze_text_rules(
        "Install AnyDesk and give me remote access so I can fix your bank account."
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }

    assert (
        "REMOTE ACCESS"
        in result["dangerous_actions"]
    )


def test_digital_arrest_pattern_is_detected():
    result = analyze_text_rules(
        "This is a police case. Your Aadhaar is linked to illegal activity. "
        "Stay on the video call and follow our instructions."
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }

    assert "digital_arrest" in result["categories"]


def test_job_scam_pattern_is_detected():
    result = analyze_text_rules(
        "Congratulations, you have been selected for a work-from-home job. "
        "Pay a registration fee to start."
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }

    assert "job" in result["categories"]


def test_investment_scam_pattern_is_detected():
    result = analyze_text_rules(
        "Invest today and get guaranteed 50 percent returns. "
        "Send the investment amount now."
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }

    assert "investment" in result["categories"]


def test_qr_payment_pattern_is_detected():
    result = analyze_text_rules(
        "Scan this QR code to receive your refund."
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }

    assert "payment_qr" in result["categories"]


def test_secrecy_signal_is_detected():
    result = analyze_text_rules(
        "Do not tell your family about this transaction."
    )

    assert "secrecy" in result["signal_groups"]


def test_normal_message_is_not_critical():
    result = analyze_text_rules(
        "Hello, your electricity bill was generated successfully."
    )

    assert result["risk"] != "CRITICAL"


def test_multiple_scam_signals_increase_risk():
    result = analyze_text_rules(
        "Your bank account will be blocked today. "
        "Share your OTP and UPI PIN immediately. "
        "Do not tell anyone."
    )

    assert result["risk"] == "CRITICAL"

    assert "OTP" in result["dangerous_actions"]
    assert "UPI PIN" in result["dangerous_actions"]

    assert "urgency" in result["signal_groups"]
    assert "credential_request" in result["signal_groups"]
