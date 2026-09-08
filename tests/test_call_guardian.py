"""
Tests for ElderShield Incoming Call Guard.
"""

from modules.call_guardian import (
    assess_call_scenario,
    assess_call_text,
)


def test_unknown_caller_is_caution():
    result = assess_call_scenario(
        "unknown"
    )

    assert result["risk"] == "CAUTION"


def test_unknown_caller_is_not_automatically_scam():
    result = assess_call_scenario(
        "unknown"
    )

    assert result["risk"] != "CRITICAL"


def test_bank_urgency_call_is_high_risk():
    result = assess_call_scenario(
        "bank_urgency"
    )

    assert result["risk"] == "HIGH"


def test_digital_arrest_call_is_high_risk():
    result = assess_call_scenario(
        "digital_arrest"
    )

    assert result["risk"] == "HIGH"


def test_job_fee_call_is_high_risk():
    result = assess_call_scenario(
        "job_fee"
    )

    assert result["risk"] == "HIGH"


def test_investment_guarantee_call_is_high_risk():
    result = assess_call_scenario(
        "investment_guarantee"
    )

    assert result["risk"] == "HIGH"


def test_normal_call_is_safe():
    result = assess_call_scenario(
        "normal"
    )

    assert result["risk"] == "SAFE"


def test_otp_request_is_critical():
    result = assess_call_text(
        "I am calling from your bank. "
        "Tell me the OTP immediately."
    )

    assert result["risk"] == "CRITICAL"
    assert "OTP" in result["dangerous_actions"]


def test_upi_pin_request_is_critical():
    result = assess_call_text(
        "Give me your UPI PIN to process the refund."
    )

    assert result["risk"] == "CRITICAL"
    assert "UPI PIN" in result["dangerous_actions"]


def test_remote_access_request_is_critical():
    result = assess_call_text(
        "Install AnyDesk and give me remote access "
        "to fix your banking problem."
    )

    assert result["risk"] == "CRITICAL"

    assert (
        "REMOTE ACCESS"
        in result["dangerous_actions"]
    )


def test_password_request_is_critical():
    result = assess_call_text(
        "Tell me your internet banking password."
    )

    assert result["risk"] == "CRITICAL"

    assert (
        "PASSWORD"
        in result["dangerous_actions"]
    )


def test_money_transfer_request_is_critical():
    result = assess_call_text(
        "Transfer the money to this account immediately."
    )

    assert result["risk"] == "CRITICAL"


def test_suspicious_call_combines_multiple_signals():
    result = assess_call_text(
        "This is the police. Your Aadhaar is involved "
        "in a criminal case. Stay on the call and "
        "transfer money immediately."
    )

    assert result["risk"] == "CRITICAL"

    assert len(
        result["reasons"]
    ) > 0
