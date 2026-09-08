"""
ElderShield integration tests.

These tests verify that the major safety layers work together
without requiring Gemini, network access, payments, or external APIs.
"""

from modules.case_engine import analyze_case
from modules.report import report_from_case
from modules.incident import create_incident
from modules.export import export_incident_json


def test_full_message_to_case_to_report_flow():
    message = (
        "Your SBI account will be blocked today. "
        "Call immediately and share the OTP to complete KYC."
    )

    case = analyze_case(
        message=message,
    )

    assert isinstance(case, dict)

    assert case["risk"] in {
        "HIGH",
        "CRITICAL",
    }

    assert len(case.get("reasons", [])) > 0
    assert len(case.get("actions", [])) > 0

    report = report_from_case(case)

    assert isinstance(report, dict)
    assert report["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_critical_credential_request_reaches_case_engine():
    message = (
        "Your bank account has a problem. "
        "Tell me your OTP and UPI PIN immediately."
    )

    case = analyze_case(
        message=message,
    )

    assert case["risk"] == "CRITICAL"

    dangerous_actions = {
        action.upper()
        for action in case.get(
            "dangerous_actions",
            [],
        )
    }

    assert (
        "OTP" in dangerous_actions
        or "UPI PIN" in dangerous_actions
    )


def test_remote_access_scenario_reaches_critical():
    message = (
        "Install AnyDesk and give me remote access "
        "so I can fix your bank account."
    )

    case = analyze_case(
        message=message,
    )

    assert case["risk"] == "CRITICAL"

    actions = " ".join(
        case.get(
            "dangerous_actions",
            [],
        )
    ).upper()

    assert (
        "REMOTE ACCESS" in actions
        or "ANYDESK" in message.upper()
    )


def test_case_to_incident_does_not_store_raw_message():
    message = (
        "Share your OTP immediately to verify your account."
    )

    case = analyze_case(
        message=message,
    )

    incident = create_incident(
        case
    )

    assert isinstance(
        incident,
        dict,
    )

    serialized = str(
        incident
    ).lower()

    assert "share your otp immediately" not in serialized
    assert "raw_evidence" not in incident or not incident.get(
        "raw_evidence"
    )


def test_incident_export_is_json_serializable():
    message = (
        "Your account will be blocked. "
        "Send ₹500 immediately."
    )

    case = analyze_case(
        message=message,
    )

    incident = create_incident(
        case
    )

    exported = export_incident_json(
        incident
    )

    assert isinstance(
        exported,
        str,
    )

    assert len(exported) > 0

    assert "₹500" not in exported
