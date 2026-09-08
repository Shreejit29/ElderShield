"""
Tests for ElderShield local health checks.
"""

from modules.health_check import (
    check_core_modules,
    check_data_files,
    check_project_structure,
    health_summary,
    run_health_check,
)


def test_core_modules_are_available():
    result = check_core_modules()

    assert isinstance(result, dict)
    assert result["checked"] > 0
    assert result["ok"] is True
    assert result["failed"] == []


def test_required_data_files_are_available():
    result = check_data_files()

    assert isinstance(result, dict)
    assert result["checked"] > 0
    assert result["ok"] is True
    assert result["missing"] == []


def test_project_structure_is_available():
    result = check_project_structure()

    assert isinstance(result, dict)
    assert result["ok"] is True
    assert result["missing"] == []


def test_full_health_check_passes():
    result = run_health_check()

    assert isinstance(result, dict)
    assert result["ok"] is True
    assert "checks" in result

    assert result["checks"]["core_modules"]["ok"] is True
    assert result["checks"]["data_files"]["ok"] is True
    assert result["checks"]["project_structure"]["ok"] is True


def test_health_summary_is_human_readable():
    summary = health_summary()

    assert isinstance(summary, str)
    assert len(summary) > 0
    assert "ElderShield" in summary


def test_health_check_does_not_expose_secrets():
    result = run_health_check()

    serialized = str(result).lower()

    assert "gemini_api_key" not in serialized
    assert "api_key=" not in serialized
    assert "password=" not in serialized
    assert "otp=" not in serialized
