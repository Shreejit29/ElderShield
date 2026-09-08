"""
ElderShield QR Analyzer

Extracts QR codes from uploaded images and provides the
decoded payload for further ElderShield analysis.

IMPORTANT:
- A decoded QR code is untrusted content.
- Never assume a QR code is safe because it decodes successfully.
- QR payloads must be analyzed before the user acts on them.
- ElderShield must never ask for a UPI PIN, OTP, password,
  ATM PIN, or other secret.
"""

from __future__ import annotations

from typing import Any

import cv2
import numpy as np


# ============================================================
# CONFIGURATION
# ============================================================

MAX_IMAGE_SIZE = 12 * 1024 * 1024  # 12 MB


# ============================================================
# HELPERS
# ============================================================

def _empty_result(
    message: str,
) -> dict[str, Any]:
    """
    Return a standardized QR-analysis result.
    """

    return {
        "found": False,
        "payloads": [],
        "count": 0,
        "message": message,
    }


# ============================================================
# QR DECODING
# ============================================================

def decode_qr(
    image_bytes: bytes,
) -> dict[str, Any]:
    """
    Detect and decode one or more QR codes from an image.

    Returns:
        {
            "found": bool,
            "payloads": [...],
            "count": int,
            "message": str
        }

    This function performs local decoding only.
    It does not open URLs or contact external servers.
    """

    if not isinstance(
        image_bytes,
        bytes,
    ) or not image_bytes:

        return _empty_result(
            "No image was provided."
        )

    if len(image_bytes) > MAX_IMAGE_SIZE:

        return _empty_result(
            "The image is too large for QR analysis."
        )

    try:

        image_array = np.frombuffer(
            image_bytes,
            dtype=np.uint8,
        )

        image = cv2.imdecode(
            image_array,
            cv2.IMREAD_COLOR,
        )

        if image is None:

            return _empty_result(
                "The image could not be decoded."
            )

        detector = cv2.QRCodeDetector()

        # ----------------------------------------------------
        # Try multiple QR codes first.
        # ----------------------------------------------------

        try:

            result = detector.detectAndDecodeMulti(
                image
            )

            if result is not None:

                success, decoded_info, _, _ = result

                if success and decoded_info:

                    payloads = []

                    for value in decoded_info:

                        if not isinstance(
                            value,
                            str,
                        ):
                            continue

                        value = value.strip()

                        if value:
                            payloads.append(
                                value
                            )

                    payloads = list(
                        dict.fromkeys(
                            payloads
                        )
                    )

                    if payloads:

                        return {
                            "found": True,
                            "payloads": payloads,
                            "count": len(payloads),
                            "message": (
                                f"Detected {len(payloads)} QR code(s)."
                            ),
                        }

        except Exception:
            # Fall back to single QR detection.
            pass

        # ----------------------------------------------------
        # Single QR fallback.
        # ----------------------------------------------------

        try:

            data, points, _ = detector.detectAndDecode(
                image
            )

            if points is not None and data:

                value = data.strip()

                if value:

                    return {
                        "found": True,
                        "payloads": [value],
                        "count": 1,
                        "message": "Detected 1 QR code.",
                    }

        except Exception:
            pass

        return _empty_result(
            "No readable QR code was detected."
        )

    except Exception as exc:

        return _empty_result(
            f"QR analysis failed: {type(exc).__name__}"
        )


# ============================================================
# PAYLOAD CLASSIFICATION
# ============================================================

def classify_qr_payload(
    payload: str,
) -> dict[str, Any]:
    """
    Perform a lightweight classification of a decoded QR
    payload.

    This does NOT open URLs and does NOT perform payments.
    """

    value = str(
        payload or ""
    ).strip()

    if not value:

        return {
            "type": "UNKNOWN",
            "risk_hint": "UNKNOWN",
            "summary": "The QR code contains no readable data.",
        }

    lower = value.lower()

    # --------------------------------------------------------
    # UPI
    # --------------------------------------------------------

    if lower.startswith(
        "upi://"
    ):

        return {
            "type": "UPI",
            "risk_hint": "CAUTION",
            "summary": (
                "This QR code contains a UPI payment payload. "
                "A successful decode does not prove that the "
                "payment recipient is trustworthy."
            ),
        }

    # --------------------------------------------------------
    # HTTP / HTTPS
    # --------------------------------------------------------

    if lower.startswith(
        "https://"
    ) or lower.startswith(
        "http://"
    ):

        return {
            "type": "URL",
            "risk_hint": "CAUTION",
            "summary": (
                "This QR code contains a web address. "
                "The address should be checked before opening it."
            ),
        }

    # --------------------------------------------------------
    # Telephone
    # --------------------------------------------------------

    if lower.startswith(
        "tel:"
    ):

        return {
            "type": "PHONE",
            "risk_hint": "CAUTION",
            "summary": (
                "This QR code contains a telephone number."
            ),
        }

    # --------------------------------------------------------
    # Email
    # --------------------------------------------------------

    if lower.startswith(
        "mailto:"
    ):

        return {
            "type": "EMAIL",
            "risk_hint": "CAUTION",
            "summary": (
                "This QR code contains an email address."
            ),
        }

    # --------------------------------------------------------
    # Generic text
    # --------------------------------------------------------

    return {
        "type": "TEXT",
        "risk_hint": "UNKNOWN",
        "summary": (
            "The QR code contains text or another data format."
        ),
    }


# ============================================================
# COMPLETE QR ANALYSIS
# ============================================================

def analyze_qr(
    image_bytes: bytes,
) -> dict[str, Any]:
    """
    Decode and classify QR codes from an image.

    No external network requests are made.
    """

    decoded = decode_qr(
        image_bytes
    )

    if not decoded["found"]:

        return decoded

    results = []

    overall_risk = "SAFE"

    risk_order = {
        "SAFE": 0,
        "UNKNOWN": 1,
        "CAUTION": 2,
        "HIGH RISK": 3,
        "CRITICAL": 4,
    }

    for payload in decoded["payloads"]:

        classification = classify_qr_payload(
            payload
        )

        results.append(
            {
                "payload": payload,
                **classification,
            }
        )

        current_risk = classification.get(
            "risk_hint",
            "UNKNOWN",
        )

        if risk_order.get(
            current_risk,
            1,
        ) > risk_order.get(
            overall_risk,
            0,
        ):

            overall_risk = current_risk

    return {
        "found": True,
        "payloads": decoded["payloads"],
        "count": decoded["count"],
        "message": decoded["message"],
        "results": results,
        "risk_hint": overall_risk,
    }
