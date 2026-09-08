"""
Tests for ElderShield URL analyzer.

These tests are fully offline. The URL analyzer must never need
to contact the submitted website.
"""

from modules.url_analyzer import analyze_url


def test_https_normal_url():
    result = analyze_url(
        "https://www.example.com/account"
    )

    assert result["scheme"] == "https"
    assert result["domain"] == "example.com"
    assert result["risk"] in {
        "SAFE",
        "CAUTION",
    }


def test_http_url_gets_warning():
    result = analyze_url(
        "http://example.com/login"
    )

    assert result["risk"] in {
        "CAUTION",
        "HIGH",
    }

    assert any(
        "HTTP" in str(reason).upper()
        for reason in result["reasons"]
    )


def test_raw_ip_address_is_flagged():
    result = analyze_url(
        "http://192.168.1.10/login"
    )

    assert result["risk"] in {
        "CAUTION",
        "HIGH",
    }

    assert any(
        "IP" in str(reason).upper()
        for reason in result["reasons"]
    )


def test_userinfo_url_is_flagged():
    result = analyze_url(
        "https://google.com@evil.example/login"
    )

    assert result["risk"] in {
        "CAUTION",
        "HIGH",
    }

    assert any(
        "@" in str(reason)
        or "USER" in str(reason).upper()
        for reason in result["reasons"]
    )


def test_punycode_domain_is_flagged():
    result = analyze_url(
        "https://xn--pple-43d.example/login"
    )

    assert result["risk"] in {
        "CAUTION",
        "HIGH",
    }

    assert any(
        "PUNYCODE" in str(reason).upper()
        or "NON-ASCII" in str(reason).upper()
        or "ASCII" in str(reason).upper()
        for reason in result["reasons"]
    )


def test_url_shortener_is_flagged():
    result = analyze_url(
        "https://bit.ly/3Example"
    )

    assert result["risk"] in {
        "CAUTION",
        "HIGH",
    }


def test_suspicious_keywords_are_detected():
    result = analyze_url(
        "https://example.com/verify-account-login"
    )

    assert result["risk"] in {
        "CAUTION",
        "HIGH",
    }

    assert len(result["reasons"]) > 0


def test_long_url_is_flagged():
    long_path = "a" * 2500

    result = analyze_url(
        "https://example.com/" + long_path
    )

    assert result["risk"] in {
        "CAUTION",
        "HIGH",
    }


def test_invalid_scheme_is_rejected():
    result = analyze_url(
        "javascript:alert(1)"
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_empty_url_is_not_safe():
    result = analyze_url("")

    assert result["risk"] != "SAFE"
