"""
Tests for ElderShield SSRF-safe URL validation.

These tests do not perform network requests.
"""

from modules.safe_url import (
    validate_url_for_fetch,
    is_safe_ip,
)


def test_https_public_domain_is_allowed():
    result = validate_url_for_fetch(
        "https://example.com"
    )

    assert result["allowed"] is True


def test_http_public_domain_is_allowed():
    result = validate_url_for_fetch(
        "http://example.com"
    )

    assert result["allowed"] is True


def test_localhost_is_blocked():
    result = validate_url_for_fetch(
        "http://localhost"
    )

    assert result["allowed"] is False


def test_loopback_ip_is_blocked():
    result = validate_url_for_fetch(
        "http://127.0.0.1"
    )

    assert result["allowed"] is False


def test_private_ip_is_blocked():
    result = validate_url_for_fetch(
        "http://192.168.1.1"
    )

    assert result["allowed"] is False


def test_private_10_network_is_blocked():
    result = validate_url_for_fetch(
        "http://10.0.0.1"
    )

    assert result["allowed"] is False


def test_private_172_network_is_blocked():
    result = validate_url_for_fetch(
        "http://172.16.0.1"
    )

    assert result["allowed"] is False


def test_link_local_ip_is_blocked():
    result = validate_url_for_fetch(
        "http://169.254.169.254"
    )

    assert result["allowed"] is False


def test_non_http_scheme_is_blocked():
    result = validate_url_for_fetch(
        "file:///etc/passwd"
    )

    assert result["allowed"] is False


def test_javascript_scheme_is_blocked():
    result = validate_url_for_fetch(
        "javascript:alert(1)"
    )

    assert result["allowed"] is False


def test_multicast_ip_is_not_safe():
    assert is_safe_ip(
        "224.0.0.1"
    ) is False


def test_unspecified_ipv4_is_not_safe():
    assert is_safe_ip(
        "0.0.0.0"
    ) is False


def test_loopback_ipv6_is_not_safe():
    assert is_safe_ip(
        "::1"
    ) is False


def test_private_ipv6_is_not_safe():
    assert is_safe_ip(
        "fc00::1"
    ) is False


def test_invalid_ip_is_not_safe():
    assert is_safe_ip(
        "not-an-ip"
    ) is False
