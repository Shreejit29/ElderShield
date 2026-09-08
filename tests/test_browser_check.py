"""
Tests for ElderShield browser safety checks.

The browser checker is an offline safety layer.
It must not open, execute, or interact with submitted URLs.
"""

from modules.browser_check import check_browser_url


def test_normal_https_url():
    result = check_browser_url(
        "https://example.com"
    )

    assert isinstance(
        result,
        dict,
    )

    assert result["risk"] in {
        "SAFE",
        "CAUTION",
    }


def test_http_url_gets_warning():
    result = check_browser_url(
        "http://example.com/login"
    )

    assert result["risk"] in {
        "CAUTION",
        "HIGH",
    }


def test_login_url_is_analyzed():
    result = check_browser_url(
        "https://example.com/login"
    )

    assert isinstance(
        result,
        dict,
    )

    assert "reasons" in result


def test_verify_account_url_is_analyzed():
    result = check_browser_url(
        "https://example.com/verify-account"
    )

    assert result["risk"] in {
        "CAUTION",
        "HIGH",
    }


def test_suspicious_phishing_keyword_is_detected():
    result = check_browser_url(
        "https://example.com/phishing-login"
    )

    assert result["risk"] in {
        "CAUTION",
        "HIGH",
    }


def test_encoded_url_content_is_analyzed():
    result = check_browser_url(
        "https://example.com/%76%65%72%69%66%79"
    )

    assert isinstance(
        result,
        dict,
    )


def test_invalid_scheme_is_rejected():
    result = check_browser_url(
        "javascript:alert(1)"
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_file_scheme_is_rejected():
    result = check_browser_url(
        "file:///etc/passwd"
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_empty_url_is_rejected():
    result = check_browser_url(
        ""
    )

    assert result["risk"] != "SAFE"


def test_localhost_is_not_safe():
    result = check_browser_url(
        "http://localhost:8501"
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_private_ip_is_not_safe():
    result = check_browser_url(
        "http://192.168.1.1/login"
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_browser_checker_does_not_execute_url():
    result = check_browser_url(
        "javascript:alert(document.cookie)"
    )

    serialized = str(
        result
    ).lower()

    assert "executed" not in serialized
    assert "document.cookie" not in serialized


def test_browser_checker_returns_actions():
    result = check_browser_url(
        "https://example.com/verify-account"
    )

    assert len(
        result.get(
            "actions",
            [],
        )
    ) > 0
