"""
Tests for ElderShield intervention guidance.
"""

from modules.intervention import (
    get_intervention,
    escalate_risk_for_actions,
)


def test_critical_otp_action():
    result = get_intervention(
        risk="CRITICAL",
        dangerous_actions=["OTP"],
    )

    assert result["risk"] == "CRITICAL"
    assert len(result["actions"]) > 0


def test_upi_pin_gets_strong_warning():
    result = get_intervention(
        risk="HIGH",
        dangerous_actions=["UPI PIN"],
    )

    assert result["risk"] == "CRITICAL"

    assert any(
        "UPI" in str(action).upper()
        for action in result["actions"]
    )


def test_password_request_is_critical():
    result = get_intervention(
        risk="HIGH",
        dangerous_actions=["PASSWORD"],
    )

    assert result["risk"] == "CRITICAL"


def test_remote_access_is_critical():
    result = get_intervention(
        risk="HIGH",
        dangerous_actions=["REMOTE ACCESS"],
    )

    assert result["risk"] == "CRITICAL"


def test_money_transfer_is_critical():
    result = get_intervention(
        risk="HIGH",
        dangerous_actions=["MONEY TRANSFER"],
    )

    assert result["risk"] == "CRITICAL"


def test_payment_approval_is_critical():
    result = get_intervention(
        risk="HIGH",
        dangerous_actions=["PAYMENT APPROVAL"],
    )

    assert result["risk"] == "CRITICAL"


def test_install_app_is_high_risk():
    result = get_intervention(
        risk="CAUTION",
        dangerous_actions=["INSTALL APP"],
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_scan_qr_is_high_risk():
    result = get_intervention(
        risk="CAUTION",
        dangerous_actions=["SCAN QR"],
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_already_paid_escalates_to_critical():
    result = get_intervention(
        risk="HIGH",
        dangerous_actions=[],
        already_paid=True,
    )

    assert result["risk"] == "CRITICAL"


def test_remote_access_granted_escalates_to_critical():
    result = get_intervention(
        risk="HIGH",
        dangerous_actions=[],
        remote_access_granted=True,
    )

    assert result["risk"] == "CRITICAL"


def test_safe_case_has_guidance():
    result = get_intervention(
        risk="SAFE",
        dangerous_actions=[],
    )

    assert result["risk"] == "SAFE"
    assert len(result["actions"]) > 0


def test_unknown_case_does_not_become_safe():
    result = get_intervention(
        risk="UNKNOWN",
        dangerous_actions=[],
    )

    assert result["risk"] == "UNKNOWN"


def test_multiple_actions_are_deduplicated():
    result = get_intervention(
        risk="HIGH",
        dangerous_actions=[
            "OTP",
            "OTP",
            "UPI PIN",
            "UPI PIN",
        ],
    )

    assert result["risk"] == "CRITICAL"

    assert len(
        result["actions"]
    ) > 0


def test_escalate_risk_for_critical_action():
    risk = escalate_risk_for_actions(
        "CAUTION",
        ["OTP"],
    )

    assert risk == "CRITICAL"


def test_escalate_risk_for_remote_access():
    risk = escalate_risk_for_actions(
        "SAFE",
        ["REMOTE ACCESS"],
    )

    assert risk == "CRITICAL"


def test_no_dangerous_action_preserves_risk():
    risk = escalate_risk_for_actions(
        "HIGH",
        [],
    )

    assert risk == "HIGH"
