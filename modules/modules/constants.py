"""
ElderShield Shared Constants

Central definitions used across the application.

Keeping these values in one place helps prevent inconsistent
risk levels, channels and safety actions between modules.
"""

from __future__ import annotations


# ============================================================
# APPLICATION
# ============================================================

APP_NAME = "ElderShield"

APP_VERSION = "5.0.0"

APP_TAGLINE = (
    "Show ElderShield what you are seeing, "
    "and it tells you what to do."
)


# ============================================================
# RISK LEVELS
# ============================================================

RISK_SAFE = "SAFE"

RISK_CAUTION = "CAUTION"

RISK_HIGH = "HIGH"

RISK_CRITICAL = "CRITICAL"

RISK_UNKNOWN = "UNKNOWN"


RISK_LEVELS = (
    RISK_SAFE,
    RISK_CAUTION,
    RISK_HIGH,
    RISK_CRITICAL,
    RISK_UNKNOWN,
)


RISK_PRIORITY = {
    RISK_SAFE: 0,
    RISK_UNKNOWN: 0,
    RISK_CAUTION: 1,
    RISK_HIGH: 2,
    RISK_CRITICAL: 3,
}


# ============================================================
# ANALYSIS CHANNELS
# ============================================================

CHANNEL_SCREEN = "SCREEN"

CHANNEL_MESSAGE = "MESSAGE"

CHANNEL_CALL = "CALL"

CHANNEL_AUDIO = "AUDIO"

CHANNEL_URL = "URL"

CHANNEL_QR = "QR"

CHANNEL_EMAIL = "EMAIL"

CHANNEL_ATTACHMENT = "ATTACHMENT"

CHANNEL_PHONE = "PHONE"


CHANNELS = (
    CHANNEL_SCREEN,
    CHANNEL_MESSAGE,
    CHANNEL_CALL,
    CHANNEL_AUDIO,
    CHANNEL_URL,
    CHANNEL_QR,
    CHANNEL_EMAIL,
    CHANNEL_ATTACHMENT,
    CHANNEL_PHONE,
)


# ============================================================
# DANGEROUS ACTIONS
# ============================================================

ACTION_OTP = "OTP"

ACTION_UPI_PIN = "UPI PIN"

ACTION_ATM_PIN = "ATM PIN"

ACTION_CARD_PIN = "CARD PIN"

ACTION_PASSWORD = "PASSWORD"

ACTION_CVV = "CVV"

ACTION_BANK_CREDENTIALS = "BANK CREDENTIALS"

ACTION_REMOTE_ACCESS = "REMOTE ACCESS"

ACTION_SCREEN_SHARING = "SCREEN SHARING"

ACTION_INSTALL_APP = "INSTALL APP"

ACTION_SCAN_QR = "SCAN QR"

ACTION_MONEY_TRANSFER = "MONEY TRANSFER"

ACTION_PAYMENT = "PAYMENT"

ACTION_PAYMENT_APPROVAL = "PAYMENT APPROVAL"

ACTION_CARD_DETAILS = "CARD DETAILS"


DANGEROUS_ACTIONS = (
    ACTION_OTP,
    ACTION_UPI_PIN,
    ACTION_ATM_PIN,
    ACTION_CARD_PIN,
    ACTION_PASSWORD,
    ACTION_CVV,
    ACTION_BANK_CREDENTIALS,
    ACTION_REMOTE_ACCESS,
    ACTION_SCREEN_SHARING,
    ACTION_INSTALL_APP,
    ACTION_SCAN_QR,
    ACTION_MONEY_TRANSFER,
    ACTION_PAYMENT,
    ACTION_PAYMENT_APPROVAL,
    ACTION_CARD_DETAILS,
)


# ============================================================
# SCAM CATEGORIES
# ============================================================

CATEGORY_BANK_KYC = "bank_kyc"

CATEGORY_REMOTE_ACCESS = "remote_access"

CATEGORY_DIGITAL_ARREST = "digital_arrest"

CATEGORY_COURIER = "courier"

CATEGORY_JOB = "job"

CATEGORY_INVESTMENT = "investment"

CATEGORY_PRIZE = "prize"

CATEGORY_PAYMENT_QR = "payment_qr"

CATEGORY_RECOVERY = "recovery"

CATEGORY_SIM_KYC = "sim_kyc"

CATEGORY_SEXTORTION = "sextortion"


SCAM_CATEGORIES = (
    CATEGORY_BANK_KYC,
    CATEGORY_REMOTE_ACCESS,
    CATEGORY_DIGITAL_ARREST,
    CATEGORY_COURIER,
    CATEGORY_JOB,
    CATEGORY_INVESTMENT,
    CATEGORY_PRIZE,
    CATEGORY_PAYMENT_QR,
    CATEGORY_RECOVERY,
    CATEGORY_SIM_KYC,
    CATEGORY_SEXTORTION,
)


# ============================================================
# SIGNAL GROUPS
# ============================================================

SIGNAL_URGENCY = "urgency"

SIGNAL_THREAT = "threat"

SIGNAL_AUTHORITY = "authority_impersonation"

SIGNAL_FINANCIAL_REQUEST = "financial_request"

SIGNAL_CREDENTIAL_REQUEST = "credential_request"

SIGNAL_REMOTE_ACCESS = "remote_access"

SIGNAL_SECRECY = "secrecy"

SIGNAL_SUSPICIOUS_URL = "suspicious_url"

SIGNAL_PAYMENT = "payment_request"

SIGNAL_QR = "qr_payment"

SIGNAL_SENDER_ANOMALY = "sender_anomaly"

SIGNAL_DANGEROUS_ATTACHMENT = "dangerous_attachment"


SIGNAL_GROUPS = (
    SIGNAL_URGENCY,
    SIGNAL_THREAT,
    SIGNAL_AUTHORITY,
    SIGNAL_FINANCIAL_REQUEST,
    SIGNAL_CREDENTIAL_REQUEST,
    SIGNAL_REMOTE_ACCESS,
    SIGNAL_SECRECY,
    SIGNAL_SUSPICIOUS_URL,
    SIGNAL_PAYMENT,
    SIGNAL_QR,
    SIGNAL_SENDER_ANOMALY,
    SIGNAL_DANGEROUS_ATTACHMENT,
)


# ============================================================
# PRIVACY
# ============================================================

SENSITIVE_FIELDS = (
    "password",
    "otp",
    "pin",
    "upi_pin",
    "atm_pin",
    "card_pin",
    "cvv",
    "cvc",
    "token",
    "api_key",
    "secret",
    "credential",
)


# ============================================================
# FILE LIMITS
# ============================================================

MAX_IMAGE_BYTES = 12 * 1024 * 1024

MAX_AUDIO_BYTES = 20 * 1024 * 1024

MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024

MAX_TEXT_LENGTH = 20_000

MAX_URL_LENGTH = 4_000


# ============================================================
# AI DEFAULTS
# ============================================================

DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"

AI_FAILURE_RISK = RISK_UNKNOWN


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "APP_NAME",
    "APP_VERSION",
    "APP_TAGLINE",

    "RISK_SAFE",
    "RISK_CAUTION",
    "RISK_HIGH",
    "RISK_CRITICAL",
    "RISK_UNKNOWN",
    "RISK_LEVELS",
    "RISK_PRIORITY",

    "CHANNEL_SCREEN",
    "CHANNEL_MESSAGE",
    "CHANNEL_CALL",
    "CHANNEL_AUDIO",
    "CHANNEL_URL",
    "CHANNEL_QR",
    "CHANNEL_EMAIL",
    "CHANNEL_ATTACHMENT",
    "CHANNEL_PHONE",
    "CHANNELS",

    "ACTION_OTP",
    "ACTION_UPI_PIN",
    "ACTION_ATM_PIN",
    "ACTION_CARD_PIN",
    "ACTION_PASSWORD",
    "ACTION_CVV",
    "ACTION_BANK_CREDENTIALS",
    "ACTION_REMOTE_ACCESS",
    "ACTION_SCREEN_SHARING",
    "ACTION_INSTALL_APP",
    "ACTION_SCAN_QR",
    "ACTION_MONEY_TRANSFER",
    "ACTION_PAYMENT",
    "ACTION_PAYMENT_APPROVAL",
    "ACTION_CARD_DETAILS",
    "DANGEROUS_ACTIONS",

    "CATEGORY_BANK_KYC",
    "CATEGORY_REMOTE_ACCESS",
    "CATEGORY_DIGITAL_ARREST",
    "CATEGORY_COURIER",
    "CATEGORY_JOB",
    "CATEGORY_INVESTMENT",
    "CATEGORY_PRIZE",
    "CATEGORY_PAYMENT_QR",
    "CATEGORY_RECOVERY",
    "CATEGORY_SIM_KYC",
    "CATEGORY_SEXTORTION",
    "SCAM_CATEGORIES",

    "SIGNAL_URGENCY",
    "SIGNAL_THREAT",
    "SIGNAL_AUTHORITY",
    "SIGNAL_FINANCIAL_REQUEST",
    "SIGNAL_CREDENTIAL_REQUEST",
    "SIGNAL_REMOTE_ACCESS",
    "SIGNAL_SECRECY",
    "SIGNAL_SUSPICIOUS_URL",
    "SIGNAL_PAYMENT",
    "SIGNAL_QR",
    "SIGNAL_SENDER_ANOMALY",
    "SIGNAL_DANGEROUS_ATTACHMENT",
    "SIGNAL_GROUPS",

    "SENSITIVE_FIELDS",

    "MAX_IMAGE_BYTES",
    "MAX_AUDIO_BYTES",
    "MAX_ATTACHMENT_BYTES",
    "MAX_TEXT_LENGTH",
    "MAX_URL_LENGTH",

    "DEFAULT_GEMINI_MODEL",
    "AI_FAILURE_RISK",
]
