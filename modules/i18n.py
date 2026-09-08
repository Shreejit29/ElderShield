"""
ElderShield Internationalization (i18n)

Provides a small, dependency-free translation layer for the
ElderShield interface.

The translation catalogue is kept separate from the detection
logic so scam analysis remains language-independent.

Important:
- Detection must never depend only on UI language.
- User-provided scam content may be in any supported language.
- Missing translations safely fall back to English.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = (
    Path(__file__)
    .resolve()
    .parent.parent
)

LANGUAGE_FILE = (
    BASE_DIR
    / "data"
    / "ui_languages.json"
)


DEFAULT_LANGUAGE = "en"


# ============================================================
# TRANSLATION CATALOGUE
# ============================================================

TRANSLATIONS: dict[str, dict[str, str]] = {

    "en": {
        "app_name": "ElderShield",
        "tagline": "Show ElderShield what you are seeing, and it tells you what to do.",

        "privacy_title": "Privacy & Safety",
        "privacy_message": "Do not upload OTPs, passwords, UPI PINs, ATM PINs, CVVs or other secrets.",

        "screen": "Screen",
        "message": "Message",
        "call": "Call",
        "url": "Link",
        "qr": "QR Code",

        "analyze": "Analyze",
        "check": "Check",
        "protect": "Protect",

        "stop": "STOP",
        "verify": "VERIFY",
        "protect_action": "PROTECT",

        "safe": "SAFE",
        "caution": "CAUTION",
        "high_risk": "HIGH RISK",
        "critical": "CRITICAL",
        "unknown": "UNKNOWN",

        "safe_message": "No obvious scam signal was detected.",
        "caution_message": "Be careful and verify before taking action.",
        "high_risk_message": "Strong scam indicators were detected.",
        "critical_message": "STOP. A dangerous request may be involved.",
        "unknown_message": "ElderShield could not confidently assess this content.",

        "upload_image": "Upload a screenshot or image",
        "upload_audio": "Upload a call recording",
        "enter_message": "Paste or type the message here",
        "enter_url": "Enter the link here",

        "incoming_call_guard": "Incoming Call Guard",
        "should_answer": "Should I answer?",
        "caller_not_verified": "Caller not verified",

        "do_not_share_otp": "Do not share OTP.",
        "do_not_share_pin": "Do not share your PIN.",
        "do_not_share_password": "Do not share your password.",
        "do_not_send_money": "Do not send money because of pressure.",
        "do_not_install": "Do not install unknown applications.",
        "do_not_scan_qr": "Do not scan an unexpected QR code.",

        "verify_independently": "Verify the claim using an official source.",
        "contact_bank": "Contact your bank through an official channel.",
        "tell_trusted_person": "Tell a trusted family member or person you trust.",

        "analysis": "Analysis",
        "summary": "Summary",
        "reasons": "Why ElderShield is warning you",
        "recommended_actions": "What you should do",
        "dangerous_actions": "Dangerous actions detected",
        "organizations": "Organizations detected",
        "urls": "Links detected",
        "evidence": "Evidence",

        "no_obvious_risk": "No obvious risk detected.",
        "ai_unavailable": "AI analysis is unavailable. Do not treat this as proof that the content is safe.",

        "language": "Language",
        "english": "English",
        "hindi": "हिन्दी",
        "marathi": "मराठी",
        "gujarati": "ગુજરાતી",
        "bengali": "বাংলা",
        "tamil": "தமிழ்",
        "telugu": "తెలుగు",
        "kannada": "ಕನ್ನಡ",
        "malayalam": "മലയാളം",
        "punjabi": "ਪੰਜਾਬੀ",
        "odia": "ଓଡ଼ିଆ",
        "assamese": "অসমীয়া",

        "not_guarantee": "ElderShield is a safety aid, not a guarantee.",

        "history": "History",
        "clear_history": "Clear history",

        "error": "Something went wrong.",
        "try_again": "Please try again.",

        "qr_detected": "QR code detected",
        "qr_not_detected": "No readable QR code detected",

        "url_safe_warning": "A URL looking normal does not prove that it is safe.",
        "brand_match_warning": "A matching official domain does not prove that the entire message is legitimate.",
        "brand_mismatch_warning": "The claimed organization and supplied domain do not match.",

        "emergency": "Immediate Safety Steps",
        "stop_call": "End the call.",
        "stop_payment": "Stop the payment.",
        "contact_provider": "Contact the bank or service provider immediately.",
        "preserve_evidence": "Keep screenshots, messages and transaction details.",

        "footer": "Open-source social-benefit safety project."
    },

    "hi": {
        "app_name": "ElderShield",
        "tagline": "आप जो देख रहे हैं, ElderShield को दिखाइए और यह बताएगा कि आपको क्या करना चाहिए।",

        "privacy_title": "गोपनीयता और सुरक्षा",
        "privacy_message": "OTP, पासवर्ड, UPI PIN, ATM PIN, CVV या अन्य गोपनीय जानकारी अपलोड न करें।",

        "screen": "स्क्रीन",
        "message": "संदेश",
        "call": "कॉल",
        "url": "लिंक",
        "qr": "QR कोड",

        "analyze": "जांच करें",
        "check": "जांच",
        "protect": "सुरक्षित रहें",

        "stop": "रुकें",
        "verify": "सत्यापित करें",
        "protect_action": "सुरक्षित रहें",

        "safe": "सुरक्षित",
        "caution": "सावधान",
        "high_risk": "उच्च जोखिम",
        "critical": "गंभीर खतरा",
        "unknown": "अज्ञात",

        "safe_message": "कोई स्पष्ट धोखाधड़ी संकेत नहीं मिला।",
        "caution_message": "सावधान रहें और कार्रवाई करने से पहले सत्यापित करें।",
        "high_risk_message": "धोखाधड़ी के मजबूत संकेत मिले हैं।",
        "critical_message": "रुकें। इसमें खतरनाक अनुरोध हो सकता है।",
        "unknown_message": "ElderShield इस सामग्री का विश्वसनीय आकलन नहीं कर सका।",

        "upload_image": "स्क्रीनशॉट या तस्वीर अपलोड करें",
        "upload_audio": "कॉल रिकॉर्डिंग अपलोड करें",
        "enter_message": "संदेश यहां लिखें या पेस्ट करें",
        "enter_url": "लिंक यहां डालें",

        "incoming_call_guard": "आने वाली कॉल सुरक्षा",
        "should_answer": "क्या मुझे कॉल उठानी चाहिए?",
        "caller_not_verified": "कॉलर सत्यापित नहीं है",

        "do_not_share_otp": "OTP साझा न करें।",
        "do_not_share_pin": "PIN साझा न करें।",
        "do_not_share_password": "पासवर्ड साझा न करें।",
        "do_not_send_money": "दबाव में पैसे न भेजें।",
        "do_not_install": "अनजान ऐप इंस्टॉल न करें।",
        "do_not_scan_qr": "अनजान QR कोड स्कैन न करें।",

        "verify_independently": "आधिकारिक स्रोत से दावे की स्वतंत्र रूप से जांच करें।",
        "contact_bank": "आधिकारिक माध्यम से बैंक से संपर्क करें।",
        "tell_trusted_person": "किसी भरोसेमंद परिवार के सदस्य या व्यक्ति को बताएं।",

        "analysis": "जांच",
        "summary": "सारांश",
        "reasons": "ElderShield आपको क्यों चेतावनी दे रहा है",
        "recommended_actions": "आपको क्या करना चाहिए",
        "dangerous_actions": "खतरनाक कार्रवाई मिली",
        "organizations": "संगठन मिले",
        "urls": "लिंक मिले",
        "evidence": "सबूत",

        "language": "भाषा",
        "english": "English",
        "hindi": "हिन्दी",
        "marathi": "मराठी",
        "gujarati": "ગુજરાતી",
        "bengali": "বাংলা",
        "tamil": "தமிழ்",
        "telugu": "తెలుగు",
        "kannada": "ಕನ್ನಡ",
        "malayalam": "മലയാളം",
        "punjabi": "ਪੰਜਾਬੀ",
        "odia": "ଓଡ଼ିଆ",
        "assamese": "অসমীয়া",

        "not_guarantee": "ElderShield एक सुरक्षा सहायता है, गारंटी नहीं।",

        "history": "इतिहास",
        "clear_history": "इतिहास साफ करें",

        "error": "कुछ गलत हो गया।",
        "try_again": "कृपया फिर से कोशिश करें।",

        "qr_detected": "QR कोड मिला",
        "qr_not_detected": "कोई पढ़ने योग्य QR कोड नहीं मिला",

        "url_safe_warning": "सामान्य दिखने वाला URL सुरक्षित होने की गारंटी नहीं देता।",
        "brand_match_warning": "सही आधिकारिक डोमेन मिलने का मतलब यह नहीं कि पूरा संदेश वैध है।",
        "brand_mismatch_warning": "बताए गए संगठन और दिए गए डोमेन में मेल नहीं है।",

        "emergency": "तुरंत सुरक्षा कदम",
        "stop_call": "कॉल समाप्त करें।",
        "stop_payment": "भुगतान रोकें।",
        "contact_provider": "बैंक या सेवा प्रदाता से तुरंत आधिकारिक माध्यम से संपर्क करें।",
        "preserve_evidence": "स्क्रीनशॉट, संदेश और लेन-देन की जानकारी सुरक्षित रखें।",

        "footer": "ओपन-सोर्स सामाजिक लाभ सुरक्षा परियोजना।"
    },

    "mr": {
        "app_name": "ElderShield",
        "tagline": "तुम्ही जे पाहत आहात ते ElderShield ला दाखवा आणि काय करायचे ते जाणून घ्या।",

        "privacy_title": "गोपनीयता आणि सुरक्षितता",
        "privacy_message": "OTP, पासवर्ड, UPI PIN, ATM PIN, CVV किंवा इतर गुप्त माहिती अपलोड करू नका।",

        "screen": "स्क्रीन",
        "message": "संदेश",
        "call": "कॉल",
        "url": "लिंक",
        "qr": "QR कोड",

        "analyze": "तपासा",
        "check": "तपासणी",
        "protect": "सुरक्षित रहा",

        "stop": "थांबा",
        "verify": "पडताळा",
        "protect_action": "सुरक्षित रहा",

        "safe": "सुरक्षित",
        "caution": "सावधान",
        "high_risk": "उच्च धोका",
        "critical": "गंभीर धोका",
        "unknown": "अज्ञात",

        "safe_message": "फसवणुकीचा कोणताही स्पष्ट संकेत आढळला नाही.",
        "caution_message": "सावध रहा आणि कृती करण्यापूर्वी पडताळणी करा.",
        "high_risk_message": "फसवणुकीचे ठोस संकेत आढळले आहेत.",
        "critical_message": "थांबा. यात धोकादायक विनंती असू शकते.",
        "unknown_message": "ElderShield या सामग्रीचे विश्वासार्ह मूल्यमापन करू शकला नाही.",

        "upload_image": "स्क्रीनशॉट किंवा फोटो अपलोड करा",
        "upload_audio": "कॉल रेकॉर्डिंग अपलोड करा",
        "enter_message": "संदेश येथे लिहा किंवा पेस्ट करा",
        "enter_url": "लिंक येथे टाका",

        "incoming_call_guard": "येणाऱ्या कॉलची सुरक्षा",
        "should_answer": "कॉल घ्यावा का?",
        "caller_not_verified": "कॉलरची पडताळणी झालेली नाही",

        "do_not_share_otp": "OTP शेअर करू नका.",
        "do_not_share_pin": "PIN शेअर करू नका.",
        "do_not_share_password": "पासवर्ड शेअर करू नका.",
        "do_not_send_money": "दबावाखाली पैसे पाठवू नका.",
        "do_not_install": "अनोळखी अॅप इंस्टॉल करू नका.",
        "do_not_scan_qr": "अनोळखी QR कोड स्कॅन करू नका.",

        "verify_independently": "अधिकृत स्रोताद्वारे दाव्याची स्वतंत्रपणे पडताळणी करा.",
        "contact_bank": "अधिकृत माध्यमातून बँकेशी संपर्क साधा.",
        "tell_trusted_person": "विश्वासू कुटुंबातील व्यक्तीला किंवा विश्वासू व्यक्तीला सांगा.",

        "analysis": "तपासणी",
        "summary": "सारांश",
        "reasons": "ElderShield तुम्हाला का सावध करत आहे",
        "recommended_actions": "तुम्ही काय करावे",
        "dangerous_actions": "धोकादायक कृती आढळल्या",
        "organizations": "आढळलेले संस्थान",
        "urls": "आढळलेल्या लिंक",
        "evidence": "पुरावे",

        "language": "भाषा",
        "english": "English",
        "hindi": "हिन्दी",
        "marathi": "मराठी",
        "gujarati": "ગુજરાતી",
        "bengali": "বাংলা",
        "tamil": "தமிழ்",
        "telugu": "తెలుగు",
        "kannada": "ಕನ್ನಡ",
        "malayalam": "മലയാളം",
        "punjabi": "ਪੰਜਾਬੀ",
        "odia": "ଓଡ଼ିଆ",
        "assamese": "অসমীয়া",

        "not_guarantee": "ElderShield ही सुरक्षा मदत आहे, हमी नाही.",

        "history": "इतिहास",
        "clear_history": "इतिहास साफ करा",

        "error": "काहीतरी चूक झाली.",
        "try_again": "कृपया पुन्हा प्रयत्न करा.",

        "qr_detected": "QR कोड आढळला",
        "qr_not_detected": "वाचता येणारा QR कोड आढळला नाही",

        "url_safe_warning": "सामान्य दिसणारा URL सुरक्षित आहे याची हमी देत नाही.",
        "brand_match_warning": "अधिकृत डोमेन जुळले तरी संपूर्ण संदेश वैध आहे याची हमी नाही.",
        "brand_mismatch_warning": "सांगितलेली संस्था आणि दिलेले डोमेन जुळत नाही.",

        "emergency": "तातडीची सुरक्षा पावले",
        "stop_call": "कॉल बंद करा.",
        "stop_payment": "पेमेंट थांबवा.",
        "contact_provider": "बँक किंवा सेवा प्रदात्याशी अधिकृत माध्यमातून त्वरित संपर्क साधा.",
        "preserve_evidence": "स्क्रीनशॉट, संदेश आणि व्यवहाराची माहिती जतन करा.",

        "footer": "ओपन-सोर्स सामाजिक लाभ सुरक्षा प्रकल्प."
    }
}


# ============================================================
# LANGUAGE FILE HELPERS
# ============================================================

def load_language_config() -> dict[str, Any]:
    """
    Load supported languages from data/ui_languages.json.
    """

    try:

        with open(
            LANGUAGE_FILE,
            "r",
            encoding="utf-8",
        ) as file:

            data = json.load(
                file
            )

        if isinstance(
            data,
            dict,
        ):

            return data

    except Exception:
        pass

    return {
        "default_language": DEFAULT_LANGUAGE,
        "languages": {
            "en": {
                "name": "English",
                "native_name": "English",
                "enabled": True
            }
        }
    }


def get_supported_languages() -> dict[str, Any]:
    """
    Return enabled languages.
    """

    config = load_language_config()

    languages = config.get(
        "languages",
        {},
    )

    if not isinstance(
        languages,
        dict,
    ):
        return {}

    return {
        code: info
        for code, info in languages.items()
        if isinstance(info, dict)
        and info.get("enabled", True)
    }


def is_supported_language(
    language: str,
) -> bool:
    """
    Check whether a language is supported.
    """

    code = str(
        language or ""
    ).strip().lower()

    return code in get_supported_languages()


# ============================================================
# TRANSLATION
# ============================================================

def translate(
    key: str,
    language: str = DEFAULT_LANGUAGE,
    **kwargs: Any,
) -> str:
    """
    Translate a UI key.

    Missing translations fall back to English.
    Missing keys fall back to the key itself.
    """

    requested = str(
        language or DEFAULT_LANGUAGE
    ).strip().lower()

    if requested not in TRANSLATIONS:

        requested = DEFAULT_LANGUAGE

    value = TRANSLATIONS.get(
        requested,
        {},
    ).get(
        key
    )

    if value is None:

        value = TRANSLATIONS[
            DEFAULT_LANGUAGE
        ].get(
            key,
            key,
        )

    try:

        return value.format(
            **kwargs
        )

    except Exception:

        return value


# ============================================================
# LANGUAGE LABEL
# ============================================================

def get_language_label(
    language: str,
) -> str:
    """
    Return the native language name.
    """

    code = str(
        language or ""
    ).strip().lower()

    languages = get_supported_languages()

    info = languages.get(
        code
    )

    if isinstance(
        info,
        dict,
    ):

        native_name = info.get(
            "native_name"
        )

        if native_name:
            return str(
                native_name
            )

        name = info.get(
            "name"
        )

        if name:
            return str(
                name
            )

    return code or DEFAULT_LANGUAGE
