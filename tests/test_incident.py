"""
Tests for ElderShield incident records.
"""

from modules.incident import (
    create_incident,
    incident_summary,
)


def sample_case():
    return {
        "risk": "CRITICAL",
        "headline": "Critical credential request",
        "summary": "A suspicious message requested an OTP.",
        "reasons": [
            "Credential request detected."
        ],
        "actions": [
            "Do not share the OTP."
        ],
        "categories": [
            "bank_kyc"
        ],
        "channels": [
            "MESSAGE"
        ],
        "dangerous_actions": [
            "OTP"
        ],
        "evidence_counts": {
            "independent_sources": 2,
            "strong_signals": 2,
            "critical_signals": 1,
        },
        "raw_message": "My OTP is 123456",
        "password": "SuperSecretPassword",
    }


def test_create_incident_returns_dictionary():
    incident = create_incident(
        sample_case()
    )

    assert isinstance(
        incident,
        dict,
    )


def test_incident_has_id():
    incident = create_incident(
        sample_case()
    )

    assert "incident_id" in incident
    assert len(
        str(incident["incident_id"])
    ) > 0


def test_incident_has_timestamp():
    incident = create_incident(
        sample_case()
    )

    assert "timestamp" in incident
    assert len(
        str(incident["timestamp"])
    ) > 0


def test_incident_preserves_risk():
    incident = create_incident(
        sample_case()
    )

    assert incident["risk"] == "CRITICAL"


def test_incident_preserves_safe_metadata():
    incident = create_incident(
        sample_case()
    )

    assert incident["categories"] == [
        "bank_kyc"
    ]

    assert incident["channels"] == [
        "MESSAGE"
    ]

    assert incident["dangerous_actions"] == [
        "OTP"
    ]


def test_raw_message_is_not_stored():
    incident = create_incident(
        sample_case()
    )

    serialized = str(incident)

    assert "My OTP is 123456" not in serialized
    assert "123456" not in serialized


def test_password_is_not_stored():
    incident = create_incident(
        sample_case()
    )

    serialized = str(incident)

    assert "SuperSecretPassword" not in serialized


def test_raw_evidence_is_marked_as_not_stored():
    incident = create_incident(
        sample_case()
    )

    serialized = str(
        incident
    ).lower()

    assert (
        "raw evidence" in serialized
        or "not stored" in serialized
        or incident.get(
            "raw_evidence_stored",
            False,
        ) is False
    )


def test_incident_summary_returns_string():
    incident = create_incident(
        sample_case()
    )

    summary = incident_summary(
        incident
    )

    assert isinstance(
        summary,
        str,
    )

    assert len(summary) > 0


def test_incident_summary_contains_risk():
    incident = create_incident(
        sample_case()
    )

    summary = incident_summary(
        incident
    )

    assert "CRITICAL" in summary


def test_incident_summary_does_not_expose_credentials():
    incident = create_incident(
        sample_case()
    )

    summary = incident_summary(
        incident
    )

    assert "123456" not in summary
    assert "SuperSecretPassword" not in summary
