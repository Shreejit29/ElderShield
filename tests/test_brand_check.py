"""
Tests for ElderShield organization and brand verification.
"""

from modules.brand_check import check_brand


def test_sbi_official_domain_matches():
    result = check_brand(
        text="Your SBI account requires verification.",
        url="https://www.sbi.co.in/account",
    )

    assert result["status"] == "MATCH"


def test_sbi_fake_domain_is_mismatch():
    result = check_brand(
        text="Your SBI account requires verification.",
        url="https://sbi-security.example.com/login",
    )

    assert result["status"] == "MISMATCH"

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_uidai_official_domain_matches():
    result = check_brand(
        text="UIDAI verification is required.",
        url="https://uidai.gov.in/",
    )

    assert result["status"] == "MATCH"


def test_income_tax_official_domain_matches():
    result = check_brand(
        text="Income Tax notice.",
        url="https://www.incometax.gov.in/",
    )

    assert result["status"] == "MATCH"


def test_rbi_official_domain_matches():
    result = check_brand(
        text="RBI information.",
        url="https://www.rbi.org.in/",
    )

    assert result["status"] == "MATCH"


def test_india_post_official_domain_matches():
    result = check_brand(
        text="India Post delivery update.",
        url="https://www.indiapost.gov.in/",
    )

    assert result["status"] == "MATCH"


def test_irctc_official_domain_matches():
    result = check_brand(
        text="IRCTC booking information.",
        url="https://www.irctc.co.in/",
    )

    assert result["status"] == "MATCH"


def test_epfo_official_domain_matches():
    result = check_brand(
        text="EPFO account information.",
        url="https://www.epfindia.gov.in/",
    )

    assert result["status"] == "MATCH"


def test_digilocker_official_domain_matches():
    result = check_brand(
        text="DigiLocker document information.",
        url="https://www.digilocker.gov.in/",
    )

    assert result["status"] == "MATCH"


def test_claimed_bank_with_unrelated_domain_is_high_risk():
    result = check_brand(
        text="SBI customer care: verify your account.",
        url="https://example.com/login",
    )

    assert result["status"] == "MISMATCH"

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_unknown_organization_returns_unknown():
    result = check_brand(
        text="Acme Corporation requires verification.",
        url="https://acme.example.com/",
    )

    assert result["status"] in {
        "UNKNOWN",
        "MISMATCH",
    }


def test_brand_match_is_not_automatically_safe():
    result = check_brand(
        text="SBI: share your OTP immediately.",
        url="https://www.sbi.co.in/",
    )

    assert result["status"] == "MATCH"

    # A genuine-looking domain does not make a dangerous
    # credential request safe.
    assert result["risk"] != "SAFE"


def test_brand_result_contains_organization_information():
    result = check_brand(
        text="Your SBI account requires verification.",
        url="https://www.sbi.co.in/",
    )

    assert "organization" in result
    assert len(
        str(result["organization"])
    ) > 0


def test_brand_result_contains_reasons():
    result = check_brand(
        text="Your SBI account requires verification.",
        url="https://example.com/login",
    )

    assert len(
        result.get(
            "reasons",
            [],
        )
    ) > 0
