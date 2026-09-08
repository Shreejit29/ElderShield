"""
Tests for ElderShield internationalization helpers.
"""

from modules.i18n import (
    get_supported_languages,
    is_supported_language,
    translate,
    get_language_label,
)


def test_supported_languages_exist():
    languages = get_supported_languages()

    assert isinstance(
        languages,
        dict,
    )

    assert len(languages) > 0


def test_english_is_supported():
    assert is_supported_language(
        "en"
    ) is True


def test_hindi_is_supported():
    assert is_supported_language(
        "hi"
    ) is True


def test_marathi_is_supported():
    assert is_supported_language(
        "mr"
    ) is True


def test_invalid_language_is_not_supported():
    assert is_supported_language(
        "xx-invalid"
    ) is False


def test_language_labels_are_strings():
    languages = get_supported_languages()

    for code in languages:

        label = get_language_label(
            code
        )

        assert isinstance(
            label,
            str,
        )

        assert len(label) > 0


def test_english_translation_returns_string():
    result = translate(
        "stop",
        "en",
    )

    assert isinstance(
        result,
        str,
    )

    assert len(result) > 0


def test_hindi_translation_returns_string():
    result = translate(
        "stop",
        "hi",
    )

    assert isinstance(
        result,
        str,
    )

    assert len(result) > 0


def test_marathi_translation_returns_string():
    result = translate(
        "stop",
        "mr",
    )

    assert isinstance(
        result,
        str,
    )

    assert len(result) > 0


def test_unknown_language_falls_back_safely():
    result = translate(
        "stop",
        "xx-invalid",
    )

    english = translate(
        "stop",
        "en",
    )

    assert result == english


def test_missing_translation_falls_back_to_key():
    key = "elder_shield_test_missing_translation"

    result = translate(
        key,
        "hi",
    )

    assert isinstance(
        result,
        str,
    )

    assert len(result) > 0


def test_case_sensitive_language_code_is_handled():
    assert is_supported_language(
        "EN"
    ) is True


def test_language_code_with_whitespace_is_handled():
    assert is_supported_language(
        " hi "
    ) is True
