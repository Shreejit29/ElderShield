"""
ElderShield Input Validators

Central validation helpers for:
- Text
- URLs
- Uploaded files
- Call descriptions

Validation happens before analysis.

Important:
Validation does NOT determine whether something is a scam.
It only checks whether the supplied input is suitable for analysis.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


# ============================================================
# LIMITS
# ============================================================

MAX_MESSAGE_LENGTH = 20_000
MAX_CALL_TEXT_LENGTH = 20_000
MAX_URL_LENGTH = 4_000

MAX_IMAGE_BYTES = 12 * 1024 * 1024
MAX_AUDIO_BYTES = 20 * 1024 * 1024

ALLOWED_URL_SCHEMES = {
    "http",
    "https",
}


# ============================================================
# RESULT HELPERS
# ============================================================

def _result(
    valid: bool,
    reason: str = "",
    normalized: str = "",
) -> dict[str, Any]:
    """
    Create a standardized validation result.
    """

    return {
        "valid": bool(valid),
        "reason": str(reason),
        "normalized": normalized,
    }


# ============================================================
# TEXT VALIDATION
# ============================================================

def validate_text(
    text: Any,
    max_length: int = MAX_MESSAGE_LENGTH,
) -> dict[str, Any]:
    """
    Validate general user-provided text.

    Empty or whitespace-only text is rejected.
    """

    if text is None:

        return _result(
            False,
            "No text was provided.",
        )

    value = str(
        text
    ).strip()

    if not value:

        return _result(
            False,
            "Please enter some text.",
        )

    if max_length <= 0:

        return _result(
            False,
            "Invalid text limit.",
        )

    if len(value) > max_length:

        return _result(
            False,
            f"Text is too long. Maximum allowed length is "
            f"{max_length:,} characters.",
        )

    return _result(
        True,
        normalized=value,
    )


def validate_message(
    text: Any,
) -> dict[str, Any]:
    """
    Validate a suspicious message.
    """

    return validate_text(
        text,
        MAX_MESSAGE_LENGTH,
    )


def validate_call_text(
    text: Any,
) -> dict[str, Any]:
    """
    Validate a call description or transcript.
    """

    return validate_text(
        text,
        MAX_CALL_TEXT_LENGTH,
    )


# ============================================================
# URL VALIDATION
# ============================================================

def validate_url(
    url: Any,
) -> dict[str, Any]:
    """
    Validate basic URL syntax.

    This does NOT:
    - fetch the URL
    - prove that the site is legitimate
    - perform DNS resolution
    - bypass SSRF protection

    Network safety belongs to safe_url.py.
    """

    if url is None:

        return _result(
            False,
            "No URL was provided.",
        )

    value = str(
        url
    ).strip()

    if not value:

        return _result(
            False,
            "Please enter a URL.",
        )

    if len(value) > MAX_URL_LENGTH:

        return _result(
            False,
            f"URL is too long. Maximum allowed length is "
            f"{MAX_URL_LENGTH:,} characters.",
        )

    # Reject whitespace inside URLs.
    if re.search(
        r"\s",
        value,
    ):

        return _result(
            False,
            "The URL contains spaces.",
        )

    # A URL without a scheme is ambiguous.
    parsed = urlparse(
        value
    )

    if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:

        return _result(
            False,
            "Only HTTP and HTTPS URLs are supported.",
        )

    if not parsed.netloc:

        return _result(
            False,
            "The URL does not contain a valid domain.",
        )

    if parsed.username or parsed.password:

        return _result(
            False,
            "URLs containing embedded usernames or passwords "
            "are not accepted.",
        )

    hostname = parsed.hostname

    if not hostname:

        return _result(
            False,
            "The URL does not contain a valid hostname.",
        )

    if len(hostname) > 253:

        return _result(
            False,
            "The hostname is too long.",
        )

    return _result(
        True,
        normalized=value,
    )


# ============================================================
# IMAGE VALIDATION
# ============================================================

def validate_image_upload(
    uploaded_file: Any,
) -> dict[str, Any]:
    """
    Validate a Streamlit-style uploaded image.

    Actual image validation is delegated to input_guard.py.
    This function performs the basic upload boundary checks.
    """

    if uploaded_file is None:

        return _result(
            False,
            "No image was uploaded.",
        )

    try:

        data = uploaded_file.getvalue()

    except Exception:

        return _result(
            False,
            "The uploaded image could not be read.",
        )

    if not isinstance(
        data,
        (bytes, bytearray),
    ):

        return _result(
            False,
            "The uploaded image is invalid.",
        )

    size = len(
        data
    )

    if size == 0:

        return _result(
            False,
            "The uploaded image is empty.",
        )

    if size > MAX_IMAGE_BYTES:

        return _result(
            False,
            "The image is too large. Maximum size is 12 MB.",
        )

    return _result(
        True,
        normalized="image_upload",
    )


# ============================================================
# AUDIO VALIDATION
# ============================================================

def validate_audio_upload(
    uploaded_file: Any,
) -> dict[str, Any]:
    """
    Validate a Streamlit-style uploaded audio file.

    Actual audio processing is handled by gemini_audio.py.
    """

    if uploaded_file is None:

        return _result(
            False,
            "No audio file was uploaded.",
        )

    try:

        data = uploaded_file.getvalue()

    except Exception:

        return _result(
            False,
            "The uploaded audio could not be read.",
        )

    if not isinstance(
        data,
        (bytes, bytearray),
    ):

        return _result(
            False,
            "The uploaded audio is invalid.",
        )

    size = len(
        data
    )

    if size == 0:

        return _result(
            False,
            "The uploaded audio is empty.",
        )

    if size > MAX_AUDIO_BYTES:

        return _result(
            False,
            "The audio file is too large. Maximum size is 20 MB.",
        )

    return _result(
        True,
        normalized="audio_upload",
    )


# ============================================================
# PHONE NUMBER VALIDATION
# ============================================================

def validate_phone_number(
    phone: Any,
) -> dict[str, Any]:
    """
    Basic phone-number validation.

    This does not verify ownership or identity.
    """

    if phone is None:

        return _result(
            False,
            "No phone number was provided.",
        )

    value = str(
        phone
    ).strip()

    if not value:

        return _result(
            False,
            "Please enter a phone number.",
        )

    cleaned = re.sub(
        r"[\s().\-]",
        "",
        value,
    )

    if cleaned.startswith(
        "+"
    ):

        digits = cleaned[1:]

    else:

        digits = cleaned

    if not digits.isdigit():

        return _result(
            False,
            "Phone number contains invalid characters.",
        )

    if not 7 <= len(digits) <= 15:

        return _result(
            False,
            "Phone number length is invalid.",
        )

    return _result(
        True,
        normalized=value,
    )


# ============================================================
# SAFE DISPLAY
# ============================================================

def safe_display_text(
    text: Any,
    max_length: int = 500,
) -> str:
    """
    Prepare user-provided text for safe UI display.

    This is not HTML sanitization because Streamlit renders
    normal text by default. It mainly prevents excessive output.
    """

    value = str(
        text or ""
    ).strip()

    value = value.replace(
        "\x00",
        "",
    )

    if max_length <= 0:

        return ""

    if len(value) <= max_length:

        return value

    return (
        value[:max_length]
        + "…"
    )


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "MAX_MESSAGE_LENGTH",
    "MAX_CALL_TEXT_LENGTH",
    "MAX_URL_LENGTH",
    "MAX_IMAGE_BYTES",
    "MAX_AUDIO_BYTES",
    "validate_text",
    "validate_message",
    "validate_call_text",
    "validate_url",
    "validate_image_upload",
    "validate_audio_upload",
    "validate_phone_number",
    "safe_display_text",
]
