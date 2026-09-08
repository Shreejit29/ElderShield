"""
Tests for ElderShield payment safety checks.
"""

from modules.payment_check import check_payment


# ============================================================
# BASIC PAYMENT DETECTION
# ============================================================

def test_normal_payment_context_is_not_critical():
    result = check_payment(
        "I paid my electricity bill online."
    )

    assert result["risk"] != "CRITICAL"


def test_payment_request_is_detected():
    result = check_payment(
        "Please transfer Rs 500 to complete the payment."
    )

    assert result["risk"] in {
        "CAUTION",
        "HIGH",
        "CRITICAL",
    }


def test_money_transfer_is_high_risk():
    result = check_payment(
        "Transfer the money to this bank account immediately."
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


# ============================================================
# QR / UPI
# ============================================================

def test_upi_request_is_detected():
    result = check_payment(
        "Send the refund through UPI."
    )

    assert result["risk"] in {
        "CAUTION",
        "HIGH",
        "CRITICAL",
    }


def test_qr_payment_is_detected():
    result = check_payment(
        "Scan this QR code to receive your refund."
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_upi_pin_request_is_critical():
    result = check_payment(
        "Give me your UPI PIN to complete the payment."
    )

    assert result["risk"] == "CRITICAL"

    assert "UPI PIN" in result["dangerous_actions"]


# ============================================================
# FEES
# ============================================================

def test_registration_fee_is_detected():
    result = check_payment(
        "Pay a registration fee of Rs 999 to get the job."
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_processing_fee_is_detected():
    result = check_payment(
        "Pay the processing fee before we release the refund."
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_tax_payment_request_is_detected():
    result = check_payment(
        "Pay the tax immediately or your account will be blocked."
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


# ============================================================
# SCAM CONTEXTS
# ============================================================

def test_job_payment_scam():
    result = check_payment(
        "You got the job. Pay Rs 2000 as a security deposit."
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_investment_payment_scam():
    result = check_payment(
        "Invest Rs 10000 today and receive guaranteed returns."
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_prize_payment_scam():
    result = check_payment(
        "You won a prize. Pay the processing fee to claim it."
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


def test_kYC_payment_scam():
    result = check_payment(
        "Pay Rs 500 to complete your bank KYC."
    )

    assert result["risk"] in {
        "HIGH",
        "CRITICAL",
    }


# ============================================================
# CREDENTIAL + PAYMENT COMBINATION
# ============================================================

def test_payment_and_otp_is_critical():
    result = check_payment(
        "Transfer Rs 500 and share the OTP to confirm."
    )

    assert result["risk"] == "CRITICAL"

    assert "OTP" in result["dangerous_actions"]


def test_payment_and_password_is_critical():
    result = check_payment(
        "Pay the amount and give me your banking password."
    )

    assert result["risk"] == "CRITICAL"

    assert "PASSWORD" in result["dangerous_actions"]


def test_payment_and_cvv_is_critical():
    result = check_payment(
        "Pay the amount and send your card CVV."
    )

    assert result["risk"] == "CRITICAL"


# ============================================================
# AMOUNT EXTRACTION
# ============================================================

def test_rupee_amount_is_extracted():
    result = check_payment(
        "Please transfer Rs 2500 immediately."
    )

    amounts = result.get(
        "amounts",
        [],
    )

    assert len(amounts) > 0


def test_inr_amount_is_extracted():
    result = check_payment(
        "Pay INR 1500 as the processing fee."
    )

    amounts = result.get(
        "amounts",
        [],
    )

    assert len(amounts) > 0


# ============================================================
# SAFETY GUIDANCE
# ============================================================

def test_payment_result_has_actions():
    result = check_payment(
        "Scan this QR code and pay Rs 1000."
    )

    assert len(
        result.get(
            "actions",
            [],
        )
    ) > 0


def test_payment_checker_does_not_process_payment():
    result = check_payment(
        "Pay Rs 500 now."
    )

    # The checker should analyze the request only.
    assert "transaction_id" not in result
    assert "payment_completed" not in result
