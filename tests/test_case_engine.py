"""
Tests for ElderShield central case engine.
"""

from modules.case_engine import analyze_case


def test_empty_case_returns_unknown():
    result = analyze_case()

    assert result["risk"] == "UNKNOWN"


def test_safe_message():
    result = analyze_case(
        message=(
            "Hello, your electricity bill was generated "
            "successfully. Thank you."
        )
    )

    assert result["risk"] != "CRITICAL"


def test_otp_request_escalates_to_critical():
    result = analyze_case(
        message=(
            "Your bank account will be blocked. "
            "Share the OTP immediately."
        )
    )

    assert result["risk"] == "CRITICAL"

    assert "OTP" in result["dangerous_actions"]


def test_upi_pin_request_escalates_to_critical():
    result = analyze_case(
        message=(
            "Give me your UPI PIN to complete the refund."
        )
    )

    assert result["risk"] == "CRITICAL"

    assert "UPI PIN" in result["dangerous_actions"]


def test_remote_access_escalates_risk():
    result = analyze_case(
        message=(
            "Install AnyDesk and give me remote access "
            "to fix your bank account."
        )
    )

    assert result["risk"] == "CRITICAL"

    assert "REMOTE ACCESS" in result["dangerous_actions"]


def test_digital_arrest_is_detected():
    result = analyze_case(
        message=(
            "This is a police case. Your Aadhaar is linked "
            "to illegal activity. Stay on the video call."
        )
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }

    assert "digital_arrest" in result["categories"]


def test_job_scam_is_detected():
    result = analyze_case(
        message=(
            "You have been selected for a work-from-home job. "
            "Pay a registration fee to begin."
        )
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }

    assert "job" in result["categories"]


def test_investment_scam_is_detected():
    result = analyze_case(
        message=(
            "Guaranteed 50 percent investment returns. "
            "Send the investment amount today."
        )
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }

    assert "investment" in result["categories"]


def test_call_channel_is_recorded():
    result = analyze_case(
        call=(
            "This is your bank. Your account will be blocked "
            "unless you verify it immediately."
        )
    )

    assert "CALL" in result["channels"]


def test_message_channel_is_recorded():
    result = analyze_case(
        message=(
            "Your KYC has expired. Verify your account immediately."
        )
    )

    assert "MESSAGE" in result["channels"]


def test_multiple_channels_are_correlated():
    result = analyze_case(
        message=(
            "Your bank account will be blocked. "
            "Click the verification link immediately."
        ),
        call=(
            "We are calling from the bank. "
            "Complete the verification now."
        ),
    )

    assert len(result["channels"]) >= 2

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_critical_action_overrides_weak_evidence():
    result = analyze_case(
        message=(
            "Please provide your password to verify your account."
        )
    )

    assert result["risk"] == "CRITICAL"

    assert "PASSWORD" in result["dangerous_actions"]


def test_already_paid_escalates_to_critical():
    result = analyze_case(
        message=(
            "I already paid the registration fee."
        ),
        already_paid=True,
    )

    assert result["risk"] == "CRITICAL"


def test_remote_access_granted_escalates_to_critical():
    result = analyze_case(
        message=(
            "I already installed AnyDesk and gave them access."
        ),
        remote_access_granted=True,
    )

    assert result["risk"] == "CRITICAL"


def test_result_contains_standard_fields():
    result = analyze_case(
        message=(
            "Your KYC needs verification."
        )
    )

    required_fields = {
        "risk",
        "summary",
        "reasons",
        "actions",
        "headline",
        "priority",
        "categories",
        "dangerous_actions",
        "signal_groups",
        "channels",
    }

    assert required_fields.issubset(
        result.keys()
    )


def test_ai_failure_does_not_make_case_safe():
    result = analyze_case(
        message=(
            "Please share your OTP."
        ),
        ai_result={
            "risk": "UNKNOWN",
            "summary": "AI unavailable",
        },
    )

    assert result["risk"] == "CRITICAL"
