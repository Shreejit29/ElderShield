"""
Tests for ElderShield recovery and damage-control guidance.
"""

from modules.recovery import get_recovery_guidance


def test_no_incident_returns_general_guidance():
    result = get_recovery_guidance()

    assert isinstance(result, dict)

    assert len(
        result.get(
            "actions",
            [],
        )
    ) > 0


def test_money_sent_requires_immediate_action():
    result = get_recovery_guidance(
        money_sent=True
    )

    assert result["risk"] == "CRITICAL"

    actions = " ".join(
        str(action)
        for action in result["actions"]
    ).lower()

    assert (
        "bank" in actions
        or "payment" in actions
        or "report" in actions
    )


def test_otp_shared_is_critical():
    result = get_recovery_guidance(
        otp_shared=True
    )

    assert result["risk"] == "CRITICAL"

    assert len(
        result["actions"]
    ) > 0


def test_upi_pin_shared_is_critical():
    result = get_recovery_guidance(
        upi_pin_shared=True
    )

    assert result["risk"] == "CRITICAL"

    actions = " ".join(
        str(action)
        for action in result["actions"]
    ).lower()

    assert (
        "upi" in actions
        or "bank" in actions
        or "pin" in actions
    )


def test_password_shared_is_critical():
    result = get_recovery_guidance(
        password_shared=True
    )

    assert result["risk"] == "CRITICAL"


def test_card_details_shared_is_critical():
    result = get_recovery_guidance(
        card_details_shared=True
    )

    assert result["risk"] == "CRITICAL"


def test_remote_access_is_critical():
    result = get_recovery_guidance(
        remote_access_granted=True
    )

    assert result["risk"] == "CRITICAL"

    actions = " ".join(
        str(action)
        for action in result["actions"]
    ).lower()

    assert (
        "remote" in actions
        or "access" in actions
        or "device" in actions
    )


def test_suspicious_app_is_critical():
    result = get_recovery_guidance(
        suspicious_app_installed=True
    )

    assert result["risk"] == "CRITICAL"


def test_multiple_incidents_remain_critical():
    result = get_recovery_guidance(
        otp_shared=True,
        upi_pin_shared=True,
        money_sent=True,
        remote_access_granted=True,
    )

    assert result["risk"] == "CRITICAL"

    assert len(
        result["actions"]
    ) > 0


def test_digital_arrest_guidance():
    result = get_recovery_guidance(
        digital_arrest=True
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }

    assert len(
        result["actions"]
    ) > 0


def test_job_scam_guidance():
    result = get_recovery_guidance(
        job_scam=True
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_investment_scam_guidance():
    result = get_recovery_guidance(
        investment_scam=True
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_recovery_scam_warning_is_present():
    result = get_recovery_guidance(
        money_sent=True
    )

    combined = " ".join(
        str(value)
        for value in result.values()
    ).lower()

    assert (
        "recovery" in combined
        or "agent" in combined
        or "guarantee" in combined
    )


def test_recovery_does_not_claim_guaranteed_refund():
    result = get_recovery_guidance(
        money_sent=True
    )

    combined = " ".join(
        str(value)
        for value in result.values()
    ).lower()

    assert "guaranteed recovery" not in combined
    assert "guaranteed refund" not in combined


def test_recovery_does_not_request_credentials():
    result = get_recovery_guidance(
        otp_shared=True,
        password_shared=True,
    )

    combined = " ".join(
        str(action)
        for action in result["actions"]
    ).lower()

    assert "send your otp" not in combined
    assert "share your password" not in combined
    assert "tell me your pin" not in combined
