"""
ElderShield Application Security Helpers

Provides small, reusable security utilities for the Streamlit app.

Security principles:
- Never display API keys or secrets.
- Never log sensitive credentials.
- Treat uploaded content as untrusted.
- Keep error messages safe for end users.
- Do not store passwords, OTPs, PINs or banking credentials.
"""

from __future__ import annotations

import os
import re
from typing import Any


# ============================================================
# CONSTANTS
# ============================================================

MAX_TEXT_LENGTH = 20_000
MAX_URL_LENGTH = 4_000
MAX_FILENAME_LENGTH = 180

_SECRET_PATTERNS = (
    re.compile(
        r"(?i)(api[_ -]?key\s*[:=]\s*)[^\s,;]+"
    ),
    re.compile(
        r"(?i)(token\s*[:=]\s*)[^\s,;]+"
    ),
    re.compile(
        r"(?i)(password\s*[:=]\s*)[^\s,;]+"
    ),
    re.compile(
        r"(?i)(secret\s*[:=]\s*)[^\s,;]+"
    ),
)

# Obvious high-risk secrets.
_SENSITIVE_PATTERNS = (
    re.compile(
        r"(?i)\b(?:otp|one[\s-]?time[\s-]?password)"
        r"\s*(?:is|:|=)?\s*\d{4,8}\b"
    ),
    re.compile(
        r"(?i)\b(?:upi[\s-]?pin|atm[\s-]?pin|pin)"
        r"\s*(?:is|:|=)?\s*\d{4,6}\b"
    ),
    re.compile(
        r"(?i)\b(?:cvv|cvc)"
        r"\s*(?:is|:|=)?\s*\d{3,4}\b"
    ),
)


# ============================================================
# ENVIRONMENT / SECRET HELPERS
# ============================================================

def get_env_secret(
    name: str,
) -> str | None:
    """
    Read a secret from the environment.

    Returns None when unavailable.

    This function never raises an exception for a missing secret.
    """

    key = str(
        name or ""
    ).strip()

    if not key:

        return None

    value = os.getenv(
        key
    )

    if value is None:

        return None

    value = value.strip()

    return value or None


def get_streamlit_secret(
    name: str,
) -> str | None:
    """
    Safely read a Streamlit secret.

    Returns None if Streamlit secrets are unavailable.
    """

    key = str(
        name or ""
    ).strip()

    if not key:

        return None

    try:

        import streamlit as st

        value = st.secrets.get(
            key
        )

        if value is None:

            return None

        value = str(
            value
        ).strip()

        return value or None

    except Exception:

        return None


def get_secret(
    name: str,
) -> str | None:
    """
    Look for a secret in Streamlit secrets first,
    then environment variables.
    """

    value = get_streamlit_secret(
        name
    )

    if value:

        return value

    return get_env_secret(
        name
    )


def has_gemini_api_key() -> bool:
    """
    Return True when a Gemini API key is configured.
    """

    value = get_secret(
        "GEMINI_API_KEY"
    )

    return bool(
        value
    )


# ============================================================
# SECRET REDACTION
# ============================================================

def redact_secrets(
    text: Any,
) -> str:
    """
    Remove obvious credentials/secrets from text.

    This is intended for logs, diagnostics and UI summaries.

    It is NOT a guarantee that every secret format will be detected.
    """

    value = str(
        text or ""
    )

    for pattern in _SECRET_PATTERNS:

        value = pattern.sub(
            r"\1[REDACTED]",
            value,
        )

    for pattern in _SENSITIVE_PATTERNS:

        value = pattern.sub(
            "[SENSITIVE VALUE REDACTED]",
            value,
        )

    return value


def safe_error_message(
    error: Exception | str,
) -> str:
    """
    Convert an exception into a user-safe message.

    Internal implementation details, credentials and paths should
    not be exposed to the user.
    """

    raw = str(
        error or ""
    )

    redacted = redact_secrets(
        raw
    )

    # Avoid exposing common local/server paths.
    redacted = re.sub(
        r"(?i)(?:[A-Z]:\\|/home/|/Users/|/tmp/|/var/)"
        r"[^\s]+",
        "[internal path hidden]",
        redacted,
    )

    if not redacted.strip():

        return (
            "The analysis could not be completed. "
            "Please try again."
        )

    # Keep error messages reasonably small.
    return redacted[:500]


# ============================================================
# INPUT LIMITS
# ============================================================

def limit_text(
    text: Any,
    max_length: int = MAX_TEXT_LENGTH,
) -> str:
    """
    Safely normalize and limit text input.
    """

    value = str(
        text or ""
    )

    value = value.strip()

    if max_length <= 0:

        return ""

    return value[
        :max_length
    ]


def limit_url(
    url: Any,
) -> str:
    """
    Normalize and limit a URL before analysis.
    """

    return limit_text(
        url,
        MAX_URL_LENGTH,
    )


def safe_filename(
    filename: Any,
) -> str:
    """
    Produce a safe display/storage filename.

    This function does not create files.
    """

    value = str(
        filename or ""
    ).strip()

    if not value:

        return "uploaded_file"

    # Remove directory components.
    value = value.replace(
        "\\",
        "/",
    ).split("/")[-1]

    # Remove control characters.
    value = re.sub(
        r"[\x00-\x1f\x7f]",
        "",
        value,
    )

    # Keep a conservative set of filename characters.
    value = re.sub(
        r"[^A-Za-z0-9._() \-]",
        "_",
        value,
    )

    value = value.strip(
        " ."
    )

    if not value:

        return "uploaded_file"

    return value[
        :MAX_FILENAME_LENGTH
    ]


# ============================================================
# UNTRUSTED CONTENT
# ============================================================

def mark_as_untrusted(
    value: Any,
) -> dict[str, Any]:
    """
    Wrap externally supplied content as untrusted evidence.

    This makes the trust boundary explicit for downstream code.
    """

    return {
        "content": value,
        "trusted": False,
        "source": "user_supplied",
    }


def is_untrusted(
    value: Any,
) -> bool:
    """
    Check whether a value has been explicitly marked untrusted.
    """

    if not isinstance(
        value,
        dict,
    ):

        return False

    return value.get(
        "trusted"
    ) is False


# ============================================================
# SECURITY STATUS
# ============================================================

def security_status() -> dict[str, Any]:
    """
    Return a safe application security status.

    Secrets themselves are never returned.
    """

    return {
        "gemini_configured": has_gemini_api_key(),
        "raw_secrets_exposed": False,
        "uploads_treated_as_untrusted": True,
        "secret_redaction_enabled": True,
    }


# ============================================================
# PUBLIC API
# ============================================================

__all__ = [
    "MAX_TEXT_LENGTH",
    "MAX_URL_LENGTH",
    "MAX_FILENAME_LENGTH",
    "get_env_secret",
    "get_streamlit_secret",
    "get_secret",
    "has_gemini_api_key",
    "redact_secrets",
    "safe_error_message",
    "limit_text",
    "limit_url",
    "safe_filename",
    "mark_as_untrusted",
    "is_untrusted",
    "security_status",
]
