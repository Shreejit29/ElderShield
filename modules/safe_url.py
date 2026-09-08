"""
ElderShield Safe URL Utilities

Security boundary for any future server-side URL fetching.

This module does NOT decide whether a website is legitimate.

Its job is to determine whether ElderShield's server is allowed
to make a network request to a supplied URL.

Security goals:
- Allow only HTTP/HTTPS
- Reject localhost
- Reject loopback addresses
- Reject private addresses
- Reject link-local addresses
- Reject multicast addresses
- Reject reserved addresses
- Reject unspecified addresses
- Resolve hostnames before connecting
- Re-check every resolved IP
- Validate redirects separately
- Avoid unsafe URL schemes
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Iterable
from urllib.parse import urlsplit


# ============================================================
# CONFIGURATION
# ============================================================

ALLOWED_SCHEMES = {
    "http",
    "https",
}

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
}

MAX_HOSTNAME_LENGTH = 253


# ============================================================
# IP ADDRESS SAFETY
# ============================================================

def is_public_ip(
    ip_string: str,
) -> bool:
    """
    Return True only when an IP address is suitable for
    ordinary public Internet access.

    Private, loopback, link-local, multicast, reserved,
    unspecified and similar special-purpose addresses are
    rejected.
    """

    try:

        address = ipaddress.ip_address(
            ip_string
        )

    except ValueError:

        return False

    if address.is_private:
        return False

    if address.is_loopback:
        return False

    if address.is_link_local:
        return False

    if address.is_multicast:
        return False

    if address.is_reserved:
        return False

    if address.is_unspecified:
        return False

    return True


def validate_ip_addresses(
    addresses: Iterable[str],
) -> tuple[bool, list[str]]:
    """
    Validate a collection of resolved IP addresses.

    Returns:
        (allowed, unsafe_addresses)
    """

    unsafe = []

    for address in addresses:

        if not is_public_ip(address):
            unsafe.append(address)

    return len(unsafe) == 0, unsafe


# ============================================================
# HOSTNAME VALIDATION
# ============================================================

def validate_hostname(
    hostname: str | None,
) -> tuple[bool, str]:
    """
    Perform basic hostname validation.

    This does not resolve the hostname.
    """

    if not hostname:

        return (
            False,
            "URL does not contain a hostname.",
        )

    hostname = hostname.strip().lower()

    if len(hostname) > MAX_HOSTNAME_LENGTH:

        return (
            False,
            "Hostname is too long.",
        )

    if hostname in BLOCKED_HOSTNAMES:

        return (
            False,
            "Localhost is not allowed.",
        )

    if hostname.endswith("."):

        hostname = hostname[:-1]

    if not hostname:

        return (
            False,
            "Hostname is empty.",
        )

    return True, "Hostname format accepted."


# ============================================================
# URL VALIDATION
# ============================================================

def validate_url_for_fetch(
    url: str,
) -> tuple[bool, str]:
    """
    Validate a URL before any network request is attempted.

    Only HTTP and HTTPS are permitted.

    This function performs syntax-level checks. It does not
    perform DNS resolution.
    """

    if not isinstance(url, str):

        return (
            False,
            "URL must be a string.",
        )

    value = url.strip()

    if not value:

        return (
            False,
            "URL is empty.",
        )

    try:

        parsed = urlsplit(value)

    except Exception:

        return (
            False,
            "URL could not be parsed.",
        )

    scheme = parsed.scheme.lower()

    if scheme not in ALLOWED_SCHEMES:

        return (
            False,
            "Only HTTP and HTTPS URLs are allowed.",
        )

    # Reject URLs containing embedded credentials.
    if parsed.username is not None:
        return (
            False,
            "URLs containing embedded usernames are not allowed.",
        )

    if parsed.password is not None:
        return (
            False,
            "URLs containing embedded passwords are not allowed.",
        )

    hostname = parsed.hostname

    valid_hostname, message = validate_hostname(
        hostname
    )

    if not valid_hostname:

        return False, message

    # A literal IP can be checked immediately.
    if hostname:

        try:

            address = ipaddress.ip_address(
                hostname
            )

            if not is_public_ip(
                str(address)
            ):

                return (
                    False,
                    "The URL points to a non-public IP address.",
                )

        except ValueError:
            # Normal hostname. DNS resolution is handled separately.
            pass

    return True, "URL is eligible for network validation."


# ============================================================
# DNS RESOLUTION
# ============================================================

def resolve_hostname(
    hostname: str,
    port: int | None = None,
) -> list[str]:
    """
    Resolve a hostname to IP addresses.

    Returns a de-duplicated list of addresses.

    Raises:
        ValueError: for invalid hostnames.
        OSError: when DNS resolution fails.
    """

    valid, message = validate_hostname(
        hostname
    )

    if not valid:
        raise ValueError(message)

    if port is None:
        port = 443

    results = socket.getaddrinfo(
        hostname,
        port,
        type=socket.SOCK_STREAM,
    )

    addresses = []

    for result in results:

        sockaddr = result[4]

        if not sockaddr:
            continue

        address = sockaddr[0]

        if address not in addresses:
            addresses.append(address)

    return addresses


# ============================================================
# COMPLETE NETWORK SAFETY CHECK
# ============================================================

def validate_url_network_target(
    url: str,
) -> tuple[bool, str, list[str]]:
    """
    Validate a URL including DNS resolution.

    This is the function that should be called immediately
    before server-side network access.

    Returns:
        allowed
        explanation
        resolved IP addresses
    """

    valid, message = validate_url_for_fetch(
        url
    )

    if not valid:

        return (
            False,
            message,
            [],
        )

    parsed = urlsplit(url)

    hostname = parsed.hostname

    if not hostname:

        return (
            False,
            "URL does not contain a hostname.",
            [],
        )

    # Literal IP.
    try:

        literal_ip = ipaddress.ip_address(
            hostname
        )

        if not is_public_ip(
            str(literal_ip)
        ):

            return (
                False,
                "The destination IP is not public.",
                [],
            )

        return (
            True,
            "Public IP destination accepted.",
            [str(literal_ip)],
        )

    except ValueError:
        pass

    # Resolve normal hostname.
    try:

        addresses = resolve_hostname(
            hostname,
            parsed.port,
        )

    except Exception:

        return (
            False,
            "The hostname could not be resolved.",
            [],
        )

    if not addresses:

        return (
            False,
            "The hostname did not resolve to an address.",
            [],
        )

    allowed, unsafe_addresses = validate_ip_addresses(
        addresses
    )

    if not allowed:

        return (
            False,
            "The hostname resolves to a non-public address.",
            addresses,
        )

    return (
        True,
        "All resolved destinations are public.",
        addresses,
    )


# ============================================================
# REDIRECT VALIDATION
# ============================================================

def validate_redirect_target(
    redirect_url: str,
) -> tuple[bool, str]:
    """
    Validate a redirect destination.

    IMPORTANT:
    Redirects must be validated individually.

    A safe initial URL does NOT make its redirect destination
    automatically safe.
    """

    valid, message, _ = validate_url_network_target(
        redirect_url
    )

    return valid, message


# ============================================================
# SAFE REQUEST POLICY
# ============================================================

def get_safe_request_policy() -> dict:
    """
    Return recommended limits for any future HTTP client.

    This function does not perform a request.
    """

    return {
        "allowed_schemes": sorted(
            ALLOWED_SCHEMES
        ),
        "timeout_seconds": 8,
        "max_redirects": 5,
        "max_response_bytes": 2 * 1024 * 1024,
        "follow_redirects": True,
        "validate_every_redirect": True,
        "execute_javascript": False,
        "download_files": False,
    }
