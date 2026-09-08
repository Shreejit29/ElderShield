"""
Tests for ElderShield phone safety checks.
"""

from modules.phone_check import check_phone


# ============================================================
# NUMBER FORMAT
# ============================================================

def test_valid_indian_number():
    result = check_phone(
        "9876543210"
    )

    assert result["valid"] is True


def test_valid_indian_number_with_country_code():
    result = check_phone(
        "+919876543210"
    )

    assert result["valid"] is True


def test_invalid_short_number():
    result = check_phone(
        "12345"
    )

    assert result["valid"] is False


# ============================================================
# UNKNOWN CALLER
# ============================================================

def test_unknown_number_alone_is_not_critical():
    result = check_phone(
        "9876543210"
    )

    assert result["risk"] != "CRITICAL"


# ============================================================
# SUSPICIOUS CALL CONTEXT
# ============================================================

def test_otp_request_is_critical():
    result = check_phone(
        "9876543210",
        context="Please tell me your OTP immediately.",
    )

    assert result["risk"] == "CRITICAL"

    assert "OTP" in result["dangerous_actions"]


def test_upi_pin_request_is_critical():
    result = check_phone(
        "9876543210",
        context="Give me your UPI PIN to process the refund.",
    )

    assert result["risk"] == "CRITICAL"

    assert "UPI PIN" in result["dangerous_actions"]


def test_remote_access_request_is_critical():
    result = check_phone(
        "9876543210",
        context="Install AnyDesk and give me remote access.",
    )

    assert result["risk"] == "CRITICAL"


def test_money_transfer_request_is_critical():
    result = check_phone(
        "9876543210",
        context="Transfer the money to this account immediately.",
    )

    assert result["risk"] == "CRITICAL"


def test_bank_urgency_is_high_risk():
    result = check_phone(
        "9876543210",
        context=(
            "I am calling from your bank. "
            "Your account will be blocked today."
        ),
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_digital_arrest_context_is_high_risk():
    result = check_phone(
        "9876543210",
        context=(
            "This is the police. Your Aadhaar is linked "
            "to a criminal case."
        ),
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


# ============================================================
# SAFETY WARNINGS
# ============================================================

def test_caller_id_spoofing_warning_is_present():
    result = check_phone(
        "9876543210"
    )

    combined = " ".join(
        str(value)
        for value in result.get(
            "reasons",
            [],
        )
    ).lower()

    assert (
        "spoof" in combined
        or "caller" in combined
    )


def test_result_contains_recommended_actions():
    result = check_phone(
        "9876543210",
        context="Please share your OTP.",
    )

    assert len(
        result.get(
            "actions",
            [],
        )
    ) > 0
