"""
ElderShield Privacy-Conscious Logging

Logging rules:
- Never log OTPs, PINs, CVVs or passwords.
- Never log API keys or authentication tokens.
- Never log raw uploaded images or audio.
- Never log complete suspicious messages by default.
- Log only the minimum information required for debugging.
"""

from __future__ import annotations

import logging
import re
from typing import Any


# ============================================================
# CONSTANTS
# ============================================================

LOGGER_NAME = "eldershield"

LOG_FORMAT = (
    "%(asctime)s | "
    "%(levelname)s | "
    "%(name)s | "
    "%(message)s"
)


# ============================================================
# REDACTION PATTERNS
# ============================================================

_PATTERNS = (
    # OTP / one-time password
    (
        re.compile(
            r"(?i)\b(?:otp|one[\s-]?time[\s-]?password)"
            r"\s*(?:is|:|=)?\s*\d{4,8}\b"
        ),
        "[OTP REDACTED]",
    ),

    # UPI / ATM / generic PIN
    (
        re.compile(
            r"(?i)\b(?:upi[\s-]?pin|atm[\s-]?pin)"
            r"\s*(?:is|:|=)?\s*\d{4,6}\b"
        ),
        "[PIN REDACTED]",
    ),

    (
        re.compile(
            r"(?i)\bpin"
            r"\s*(?:is|:|=)\s*\d{4,6}\b"
        ),
        "[PIN REDACTED]",
    ),

    # CVV / CVC
    (
        re.compile(
            r"(?i)\b(?:cvv|cvc)"
            r"\s*(?:is|:|=)?\s*\d{3,4}\b"
        ),
        "[CVV REDACTED]",
    ),

    # API keys / tokens / secrets
    (
        re.compile(
            r"(?i)\b(?:api[_ -]?key|access[_ -]?token|"
            r"auth[_ -]?token|secret)"
            r"\s*[:=]\s*[^\s,;]+"
        ),
        "[SECRET REDACTED]",
    ),

    # Passwords
    (
        re.compile(
            r"(?i)\bpassword"
            r"\s*[:=]\s*[^\s,;]+"
        ),
        "[PASSWORD REDACTED]",
    ),
)


# ============================================================
# REDACTION
# ============================================================

def redact_for_log(
    value: Any,
    max_length: int = 1000,
) -> str:
    """
    Convert a value to a short, privacy-conscious log string.

    This is a best-effort redaction layer and should not be treated
    as a guarantee that every possible secret format is detected.
    """

    text = str(
        value or ""
    )

    for pattern, replacement in _PATTERNS:

        text = pattern.sub(
            replacement,
            text,
        )

    # Remove control characters.
    text = re.sub(
        r"[\x00-\x1f\x7f]",
        " ",
        text,
    )

    text = text.strip()

    if max_length <= 0:

        return ""

    if len(text) > max_length:

        return (
            text[:max_length]
            + "…"
        )

    return text


# ============================================================
# LOGGER
# ============================================================

def get_logger(
    name: str | None = None,
) -> logging.Logger:
    """
    Return an ElderShield logger.

    Logging configuration is intentionally conservative.
    """

    logger_name = (
        LOGGER_NAME
        if not name
        else f"{LOGGER_NAME}.{name}"
    )

    logger = logging.getLogger(
        logger_name
    )

    return logger


def configure_logging(
    level: int = logging.INFO,
) -> logging.Logger:
    """
    Configure the root ElderShield logger.

    Existing handlers are preserved to avoid interfering with
    Streamlit or hosting-platform logging.
    """

    logger = get_logger()

    logger.setLevel(
        level
    )

    if not logger.handlers:

        handler = logging.StreamHandler()

        handler.setFormatter(
            logging.Formatter(
                LOG_FORMAT
            )
        )

        logger.addHandler(
            handler
        )

    return logger


# ============================================================
# SAFE EVENT LOGGING
# ============================================================

def log_event(
    event: str,
    *,
    level: int = logging.INFO,
    **details: Any,
) -> None:
    """
    Log a structured event without exposing obvious secrets.

    Example:

        log_event(
            "analysis_completed",
            risk="HIGH",
            channel="message",
        )
    """

    logger = get_logger()

    safe_event = redact_for_log(
        event,
        200,
    )

    parts = [
        f"event={safe_event}"
    ]

    for key, value in details.items():

        safe_key = re.sub(
            r"[^A-Za-z0-9_.-]",
            "_",
            str(key),
        )

        # Do not log values for fields that are inherently sensitive.
        if any(
            token in safe_key.lower()
            for token in (
                "password",
                "secret",
                "token",
                "api_key",
                "apikey",
                "otp",
                "pin",
                "cvv",
                "credential",
                "raw_text",
                "transcript",
                "audio",
                "image",
                "file_content",
            )
        ):

            safe_value = "[REDACTED]"

        else:

            safe_value = redact_for_log(
                value,
                300,
            )

        parts.append(
            f"{safe_key}={safe_value}"
        )

    message = " | ".join(
        parts
    )

    logger.log(
        level,
        message,
    )


# ============================================================
# COMMON EVENTS
# ============================================================

def log_analysis_started(
    channel: str,
) -> None:
    """
    Record the start of an analysis without recording user content.
    """

    log_event(
        "analysis_started",
        channel=channel,
    )


def log_analysis_completed(
    channel: str,
    risk: str,
) -> None:
    """
    Record a completed analysis.
    """

    log_event(
        "analysis_completed",
        channel=channel,
        risk=risk,
    )


def log_analysis_failed(
    channel: str,
    error: Exception | str,
) -> None:
    """
    Record an analysis failure safely.
    """

    log_event(
        "analysis_failed",
        channel=channel,
        error=redact_for_log(
            error,
            300,
        ),
    )


def log_upload_received(
    channel: str,
    size_bytes: int,
) -> None:
    """
    Record an upload event without logging its contents or filename.
    """

    log_event(
        "upload_received",
        channel=channel,
        size_bytes=max(
            0,
            int(size_bytes),
        ),
    )


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "LOGGER_NAME",
    "LOG_FORMAT",
    "redact_for_log",
    "get_logger",
    "configure_logging",
    "log_event",
    "log_analysis_started",
    "log_analysis_completed",
    "log_analysis_failed",
    "log_upload_received",
]
