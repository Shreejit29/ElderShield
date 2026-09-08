"""
Tests for ElderShield attachment safety checks.

The attachment checker is offline and must never execute
uploaded files.
"""

from modules.attachment_check import check_attachment


def test_pdf_attachment_is_not_automatically_dangerous():
    result = check_attachment(
        filename="document.pdf",
        content_type="application/pdf",
        data=b"%PDF-1.7\n",
    )

    assert result["valid"] is True
    assert result["risk"] != "CRITICAL"


def test_png_attachment_is_allowed():
    result = check_attachment(
        filename="photo.png",
        content_type="image/png",
        data=b"\x89PNG\r\n\x1a\n",
    )

    assert result["valid"] is True
    assert result["risk"] != "CRITICAL"


def test_apk_attachment_is_dangerous():
    result = check_attachment(
        filename="bank_update.apk",
        content_type="application/vnd.android.package-archive",
        data=b"fake apk",
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_exe_attachment_is_dangerous():
    result = check_attachment(
        filename="invoice.exe",
        content_type="application/octet-stream",
        data=b"MZ",
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_script_attachment_is_dangerous():
    result = check_attachment(
        filename="update.ps1",
        content_type="text/plain",
        data=b"Write-Host test",
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_double_extension_is_flagged():
    result = check_attachment(
        filename="invoice.pdf.exe",
        content_type="application/octet-stream",
        data=b"MZ",
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_suspicious_filename_is_flagged():
    result = check_attachment(
        filename="urgent_account_update.apk",
        content_type="application/octet-stream",
        data=b"fake",
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_windows_executable_signature_is_detected():
    result = check_attachment(
        filename="document.bin",
        content_type="application/octet-stream",
        data=b"MZ\x90\x00",
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_elf_signature_is_detected():
    result = check_attachment(
        filename="unknown.bin",
        content_type="application/octet-stream",
        data=b"\x7fELF\x02\x01\x01",
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_empty_attachment_is_rejected():
    result = check_attachment(
        filename="document.pdf",
        content_type="application/pdf",
        data=b"",
    )

    assert result["valid"] is False


def test_missing_filename_is_rejected():
    result = check_attachment(
        filename="",
        content_type="application/pdf",
        data=b"%PDF-1.7\n",
    )

    assert result["valid"] is False


def test_attachment_size_limit_is_enforced():
    large_data = b"A" * (
        26 * 1024 * 1024
    )

    result = check_attachment(
        filename="large.pdf",
        content_type="application/pdf",
        data=large_data,
    )

    assert result["valid"] is False


def test_attachment_is_not_executed():
    result = check_attachment(
        filename="malware.exe",
        content_type="application/octet-stream",
        data=b"MZ\x90\x00",
    )

    assert result.get(
        "executed",
        False,
    ) is False


def test_attachment_result_contains_actions():
    result = check_attachment(
        filename="unknown.exe",
        content_type="application/octet-stream",
        data=b"MZ",
    )

    assert len(
        result.get(
            "actions",
            [],
        )
    ) > 0
