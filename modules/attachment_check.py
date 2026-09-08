"""
ElderShield Attachment Safety Checks

Conservative offline checks for suspicious attachments.

This module:
- Inspects filename and basic file signature.
- Identifies potentially dangerous file types.
- Detects double-extension tricks.
- Detects suspicious filenames.
- Never executes an attachment.
- Never opens documents through external applications.
- Never uploads an attachment to a third-party scanner.

An attachment being flagged does NOT prove that it is malicious.
"""

from __future__ import annotations

import os
import re
from typing import Any


# ============================================================
# CONSTANTS
# ============================================================

MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024
MAX_FILENAME_LENGTH = 255


DANGEROUS_EXTENSIONS = {
    ".apk",
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".com",
    ".scr",
    ".pif",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".ps1",
    ".psm1",
    ".jar",
    ".hta",
    ".reg",
    ".dll",
    ".iso",
}


ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".bz2",
}


DOCUMENT_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".txt",
    ".csv",
}


IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".bmp",
}


SUSPICIOUS_FILENAME_TERMS = (
    "urgent",
    "refund",
    "payment",
    "invoice",
    "kyc",
    "verify",
    "verification",
    "account",
    "blocked",
    "salary",
    "job",
    "prize",
    "lottery",
    "tax",
    "court",
    "police",
    "notice",
    "security",
    "update",
)


# ============================================================
# FILE SIGNATURES
# ============================================================

FILE_SIGNATURES = {
    b"%PDF-": "PDF",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"GIF87a": "GIF",
    b"GIF89a": "GIF",
    b"PK\x03\x04": "ZIP_CONTAINER",
    b"PK\x05\x06": "ZIP_CONTAINER",
    b"PK\x07\x08": "ZIP_CONTAINER",
    b"MZ": "WINDOWS_EXECUTABLE",
    b"\x7fELF": "ELF_EXECUTABLE",
}


# ============================================================
# FILENAME HELPERS
# ============================================================

def normalize_filename(
    filename: Any,
) -> str:
    """
    Normalize a filename for analysis.

    Directory components are removed.
    """

    value = str(
        filename or ""
    ).strip()

    if not value:

        return ""

    value = value.replace(
        "\\",
        "/",
    )

    value = value.split(
        "/"
    )[-1]

    value = value[:MAX_FILENAME_LENGTH]

    return value


def get_extension(
    filename: Any,
) -> str:
    """
    Return the final lowercase extension.
    """

    value = normalize_filename(
        filename
    )

    return os.path.splitext(
        value
    )[1].lower()


def get_all_extensions(
    filename: Any,
) -> list[str]:
    """
    Return all filename extensions.

    Example:
        invoice.pdf.exe
        -> [".pdf", ".exe"]
    """

    value = normalize_filename(
        filename
    ).lower()

    parts = value.split(
        "."
    )

    if len(parts) <= 1:

        return []

    return [
        "." + part
        for part in parts[1:]
        if part
    ]


# ============================================================
# FILE TYPE
# ============================================================

def classify_extension(
    filename: Any,
) -> str:
    """
    Classify the final file extension.
    """

    extension = get_extension(
        filename
    )

    if extension in DANGEROUS_EXTENSIONS:

        return "DANGEROUS"

    if extension in ARCHIVE_EXTENSIONS:

        return "ARCHIVE"

    if extension in DOCUMENT_EXTENSIONS:

        return "DOCUMENT"

    if extension in IMAGE_EXTENSIONS:

        return "IMAGE"

    if not extension:

        return "UNKNOWN"

    return "OTHER"


def detect_double_extension(
    filename: Any,
) -> bool:
    """
    Detect filename tricks such as:

        document.pdf.exe
        refund.jpg.apk
        invoice.docx.scr
    """

    extensions = get_all_extensions(
        filename
    )

    if len(extensions) < 2:

        return False

    final_extension = extensions[-1]

    earlier_extensions = extensions[:-1]

    return (
        final_extension in DANGEROUS_EXTENSIONS
        and any(
            extension in (
                DOCUMENT_EXTENSIONS
                | IMAGE_EXTENSIONS
                | ARCHIVE_EXTENSIONS
            )
            for extension in earlier_extensions
        )
    )


def suspicious_filename_terms(
    filename: Any,
) -> list[str]:
    """
    Find suspicious pressure/authority terms in a filename.
    """

    value = normalize_filename(
        filename
    ).lower()

    return [
        term
        for term in SUSPICIOUS_FILENAME_TERMS
        if term in value
    ]


# ============================================================
# FILE SIGNATURE
# ============================================================

def detect_file_signature(
    data: bytes,
) -> str:
    """
    Identify a basic file signature.

    Only the first few bytes are inspected.
    The file is never executed or fully parsed.
    """

    if not isinstance(
        data,
        bytes,
    ):

        return "UNKNOWN"

    for signature, file_type in FILE_SIGNATURES.items():

        if data.startswith(
            signature
        ):

            return file_type

    return "UNKNOWN"


# ============================================================
# ATTACHMENT ANALYSIS
# ============================================================

def analyze_attachment(
    filename: Any,
    data: bytes | bytearray | None = None,
) -> dict[str, Any]:
    """
    Analyze an attachment using offline safety rules.
    """

    safe_name = normalize_filename(
        filename
    )

    reasons: list[str] = []
    indicators: list[str] = []

    if not safe_name:

        return {
            "risk": "UNKNOWN",
            "filename": "",
            "extension": "",
            "classification": "UNKNOWN",
            "signature": "UNKNOWN",
            "size_bytes": 0,
            "reasons": [
                "No attachment filename was provided."
            ],
            "indicators": [],
            "recommended_actions": [
                "Do not open an attachment whose source you cannot verify.",
            ],
        }

    size_bytes = 0

    if data is not None:

        if not isinstance(
            data,
            (bytes, bytearray),
        ):

            return {
                "risk": "HIGH",
                "filename": safe_name,
                "extension": get_extension(
                    safe_name
                ),
                "classification": "UNKNOWN",
                "signature": "UNKNOWN",
                "size_bytes": 0,
                "reasons": [
                    "The attachment data has an unexpected format."
                ],
                "indicators": [
                    "invalid_attachment_data"
                ],
                "recommended_actions": [
                    "Do not open the attachment.",
                ],
            }

        size_bytes = len(
            data
        )

        if size_bytes > MAX_ATTACHMENT_SIZE:

            reasons.append(
                "The attachment is larger than ElderShield's "
                "recommended analysis limit."
            )

            indicators.append(
                "oversized_attachment"
            )

    extension = get_extension(
        safe_name
    )

    classification = classify_extension(
        safe_name
    )

    signature = detect_file_signature(
        bytes(data)
        if data is not None
        else b""
    )

    # --------------------------------------------------------
    # Dangerous extension
    # --------------------------------------------------------

    if extension in DANGEROUS_EXTENSIONS:

        reasons.append(
            "The attachment uses a file type that can execute "
            "code or install software."
        )

        indicators.append(
            "dangerous_extension"
        )

    # --------------------------------------------------------
    # Double extension
    # --------------------------------------------------------

    if detect_double_extension(
        safe_name
    ):

        reasons.append(
            "The filename uses a double-extension pattern that "
            "can disguise a potentially executable file."
        )

        indicators.append(
            "double_extension"
        )

    # --------------------------------------------------------
    # Suspicious filename
    # --------------------------------------------------------

    filename_terms = suspicious_filename_terms(
        safe_name
    )

    if filename_terms:

        reasons.append(
            "The filename contains terms commonly used in "
            "urgent or social-engineering messages."
        )

        indicators.append(
            "suspicious_filename"
        )

    # --------------------------------------------------------
    # Signature mismatch
    # --------------------------------------------------------

    if signature == "WINDOWS_EXECUTABLE":

        if extension not in (
            ".exe",
            ".dll",
            ".scr",
            ".com",
            ".msi",
        ):

            reasons.append(
                "The file signature indicates executable content "
                "despite its filename extension."
            )

            indicators.append(
                "signature_extension_mismatch"
            )

    if signature == "ELF_EXECUTABLE":

        reasons.append(
            "The file signature indicates executable content."
        )

        indicators.append(
            "executable_signature"
        )

    # --------------------------------------------------------
    # Risk calculation
    # --------------------------------------------------------

    if (
        "dangerous_extension" in indicators
        or "double_extension" in indicators
        or "executable_signature" in indicators
    ):

        risk = "HIGH"

    elif (
        "signature_extension_mismatch" in indicators
        or "oversized_attachment" in indicators
    ):

        risk = "HIGH"

    elif "suspicious_filename" in indicators:

        risk = "CAUTION"

    elif classification in (
        "DOCUMENT",
        "ARCHIVE",
    ):

        risk = "CAUTION"

        reasons.append(
            "Documents and archives can contain or lead to "
            "unsafe content. Verify the source before opening."
        )

    else:

        risk = "UNKNOWN"

    # --------------------------------------------------------
    # Actions
    # --------------------------------------------------------

    recommended_actions = [
        "Do not open an unexpected attachment.",
        "Verify the sender independently before opening files.",
        "Never install software because a caller or message tells you to.",
    ]

    if risk == "HIGH":

        recommended_actions.insert(
            0,
            "Do not open or execute this attachment.",
        )

    if extension in (
        ".apk",
        ".exe",
        ".msi",
        ".bat",
        ".cmd",
        ".scr",
        ".js",
        ".vbs",
        ".ps1",
    ):

        recommended_actions.insert(
            0,
            "Do not install or run the attached program.",
        )

    return {
        "risk": risk,
        "filename": safe_name,
        "extension": extension,
        "classification": classification,
        "signature": signature,
        "size_bytes": size_bytes,
        "reasons": list(
            dict.fromkeys(
                reasons
            )
        ),
        "indicators": list(
            dict.fromkeys(
                indicators
            )
        ),
        "filename_terms": filename_terms,
        "recommended_actions": list(
            dict.fromkeys(
                recommended_actions
            )
        ),
        "disclaimer": (
            "Attachment analysis provides safety signals only. "
            "It does not prove that a file is malicious or safe."
        ),
    }


# ============================================================
# STREAMLIT UPLOAD HELPER
# ============================================================

def analyze_uploaded_attachment(
    uploaded_file: Any,
) -> dict[str, Any]:
    """
    Analyze a Streamlit UploadedFile safely.

    The attachment is read into memory only for inspection.
    It is never executed.
    """

    if uploaded_file is None:

        return {
            "risk": "UNKNOWN",
            "filename": "",
            "reasons": [
                "No attachment was uploaded."
            ],
        }

    try:

        filename = uploaded_file.name

    except Exception:

        filename = "uploaded_file"

    try:

        data = uploaded_file.getvalue()

    except Exception:

        return {
            "risk": "HIGH",
            "filename": normalize_filename(
                filename
            ),
            "reasons": [
                "The attachment could not be safely read."
            ],
            "indicators": [
                "read_error"
            ],
        }

    return analyze_attachment(
        filename,
        data,
    )


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "MAX_ATTACHMENT_SIZE",
    "MAX_FILENAME_LENGTH",
    "DANGEROUS_EXTENSIONS",
    "ARCHIVE_EXTENSIONS",
    "DOCUMENT_EXTENSIONS",
    "IMAGE_EXTENSIONS",
    "normalize_filename",
    "get_extension",
    "get_all_extensions",
    "classify_extension",
    "detect_double_extension",
    "suspicious_filename_terms",
    "detect_file_signature",
    "analyze_attachment",
    "analyze_uploaded_attachment",
]
