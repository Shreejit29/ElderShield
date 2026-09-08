"""
Tests for ElderShield shared constants.
"""

from modules import constants


def test_app_identity_constants_exist():
    assert constants.APP_NAME == "ElderShield"
    assert constants.APP_VERSION
    assert constants.APP_TAGLINE


def test_risk_levels_are_present():
    expected = {
        "SAFE",
        "CAUTION",
        "HIGH",
        "CRITICAL",
    }

    assert expected.issubset(
        set(constants.RISK_LEVELS)
    )


def test_risk_priorities_exist():
    for risk in constants.RISK_LEVELS:
        assert risk in constants.RISK_PRIORITIES
        assert isinstance(
            constants.RISK_PRIORITIES[risk],
            int,
        )


def test_channels_are_defined():
    assert len(constants.CHANNELS) > 0

    for channel in constants.CHANNELS:
        assert isinstance(
            channel,
            str,
        )


def test_dangerous_actions_are_defined():
    assert len(
        constants.DANGEROUS_ACTIONS
    ) > 0

    critical_actions = {
        "OTP",
        "UPI PIN",
        "ATM PIN",
        "PASSWORD",
        "REMOTE ACCESS",
    }

    assert critical_actions.intersection(
        set(constants.DANGEROUS_ACTIONS)
    )


def test_scam_categories_are_defined():
    assert len(
        constants.SCAM_CATEGORIES
    ) > 0


def test_signal_groups_are_defined():
    expected = {
        "urgency",
        "threat",
        "authority_impersonation",
        "financial_request",
        "credential_request",
        "remote_access",
        "secrecy",
    }

    assert expected.issubset(
        set(constants.SIGNAL_GROUPS)
    )


def test_sensitive_fields_are_defined():
    assert len(
        constants.SENSITIVE_FIELDS
    ) > 0

    sensitive_text = " ".join(
        constants.SENSITIVE_FIELDS
    ).lower()

    assert "otp" in sensitive_text
    assert "password" in sensitive_text


def test_file_limits_are_positive():
    assert constants.MAX_IMAGE_BYTES > 0
    assert constants.MAX_AUDIO_BYTES > 0
    assert constants.MAX_ATTACHMENT_BYTES > 0


def test_gemini_model_is_defined():
    assert isinstance(
        constants.DEFAULT_GEMINI_MODEL,
        str,
    )

    assert (
        len(constants.DEFAULT_GEMINI_MODEL)
        > 0
    )


def test_ai_failure_is_not_safe():
    assert (
        constants.AI_FAILURE_RISK
        in {
            "UNKNOWN",
            "CAUTION",
            "HIGH",
            "CRITICAL",
        }
    )
