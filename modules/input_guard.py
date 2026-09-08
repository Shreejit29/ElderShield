"""
ElderShield Input Guard

Security layer for user-uploaded images.

Responsibilities:
- Validate file size
- Validate MIME type
- Validate actual image contents
- Prevent oversized image processing
- Provide a privacy-safe fingerprint
"""

import hashlib
import io
from typing import Tuple

from PIL import Image


# ============================================================
# CONFIGURATION
# ============================================================

MAX_IMAGE_SIZE_BYTES = 12 * 1024 * 1024  # 12 MB

ALLOWED_IMAGE_MIME_TYPES = {
    "image/png",
    "image/jpeg",
    "image/webp",
}

ALLOWED_IMAGE_FORMATS = {
    "PNG",
    "JPEG",
    "WEBP",
}


# ============================================================
# IMAGE VALIDATION
# ============================================================

def validate_image(
    image_bytes: bytes,
    mime_type: str | None = None,
) -> Tuple[bool, str]:
    """
    Validate an uploaded image before processing.

    Checks:
    1. Input exists
    2. Input is bytes
    3. File size is within the limit
    4. MIME type is allowed
    5. PIL can verify the actual image
    6. Actual image format is allowed

    Returns:
        (True, success message)
        or
        (False, error message)
    """

    # --------------------------------------------------------
    # Basic input checks
    # --------------------------------------------------------

    if not image_bytes:
        return False, "No image data was provided."

    if not isinstance(image_bytes, bytes):
        return False, "Invalid image data."

    # --------------------------------------------------------
    # File size check
    # --------------------------------------------------------

    image_size = len(image_bytes)

    if image_size > MAX_IMAGE_SIZE_BYTES:
        max_mb = MAX_IMAGE_SIZE_BYTES / (1024 * 1024)

        return (
            False,
            f"Image is too large. Maximum allowed size is {max_mb:.0f} MB.",
        )

    # --------------------------------------------------------
    # MIME type check
    # --------------------------------------------------------

    if mime_type:

        normalized_mime = mime_type.lower().strip()

        if normalized_mime not in ALLOWED_IMAGE_MIME_TYPES:

            return (
                False,
                "Unsupported image type. Please use PNG, JPEG or WebP.",
            )

    # --------------------------------------------------------
    # Validate actual image contents
    # --------------------------------------------------------

    try:

        image_stream = io.BytesIO(image_bytes)

        with Image.open(image_stream) as image:

            # verify() checks the file without fully decoding it.
            image.verify()

    except Exception:

        return (
            False,
            "The uploaded file is not a valid image.",
        )

    # --------------------------------------------------------
    # Check actual image format
    # --------------------------------------------------------

    try:

        image_stream = io.BytesIO(image_bytes)

        with Image.open(image_stream) as image:

            image_format = image.format

    except Exception:

        return (
            False,
            "Unable to determine the image format.",
        )

    if image_format not in ALLOWED_IMAGE_FORMATS:

        return (
            False,
            "Unsupported image format. Please use PNG, JPEG or WebP.",
        )

    return True, "Image is valid."


# ============================================================
# SAFE IMAGE OPENING
# ============================================================

def open_validated_image(
    image_bytes: bytes,
) -> Image.Image:
    """
    Open an image after validation.

    Raises:
        ValueError: if the image is invalid.
    """

    valid, message = validate_image(image_bytes)

    if not valid:
        raise ValueError(message)

    try:

        image = Image.open(
            io.BytesIO(image_bytes)
        )

        # Load the image into memory while the underlying stream
        # is still available.
        image.load()

        return image

    except Exception as exc:

        raise ValueError(
            "Unable to process the uploaded image."
        ) from exc


# ============================================================
# PRIVACY-SAFE FINGERPRINT
# ============================================================

def image_fingerprint(
    image_bytes: bytes,
) -> str:
    """
    Generate a SHA-256 fingerprint of image bytes.

    This is useful for detecting duplicate uploads during a
    session without storing the original image.

    The fingerprint itself does not reveal the image contents.
    """

    if not isinstance(image_bytes, bytes):
        raise TypeError(
            "image_bytes must be bytes."
        )

    return hashlib.sha256(
        image_bytes
    ).hexdigest()


# ============================================================
# IMAGE INFORMATION
# ============================================================

def get_image_info(
    image_bytes: bytes,
) -> dict:
    """
    Return basic metadata about a validated image.

    No image content is returned.
    """

    valid, message = validate_image(image_bytes)

    if not valid:
        raise ValueError(message)

    try:

        with Image.open(
            io.BytesIO(image_bytes)
        ) as image:

            return {
                "format": image.format,
                "width": image.width,
                "height": image.height,
                "size_bytes": len(image_bytes),
            }

    except Exception as exc:

        raise ValueError(
            "Unable to read image information."
        ) from exc
