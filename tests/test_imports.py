"""
ElderShield project import smoke tests.

These tests make sure all core modules can be imported together.
No network, Gemini API, payment system, or external service is used.
"""


def test_core_modules_import():
    import modules.app_security
    import modules.attachment_check
    import modules.brand_check
    import modules.browser_check
    import modules.call_guardian
    import modules.case_engine
    import modules.constants
    import modules.email_check
    import modules.evidence
    import modules.export
    import modules.feedback
    import modules.gemini_audio
    import modules.gemini_screen
    import modules.i18n
    import modules.incident
    import modules.input_guard
    import modules.intervention
    import modules.knowledge
    import modules.logging_utils
    import modules.metrics
    import modules.notifications
    import modules.official_verify
    import modules.password_check
    import modules.payment_check
    import modules.phone_check
    import modules.qr
    import modules.rate_limit
    import modules.recovery
    import modules.report
    import modules.safe_url
    import modules.session
    import modules.text_rules
    import modules.url_analyzer
    import modules.validators


def test_package_version():
    import modules

    assert hasattr(
        modules,
        "__version__",
    )

    assert isinstance(
        modules.__version__,
        str,
    )

    assert modules.__version__


def test_security_modules_do_not_require_network():
    from modules.url_analyzer import analyze_url
    from modules.safe_url import validate_url_for_fetch

    result = analyze_url(
        "https://example.com"
    )

    assert isinstance(
        result,
        dict,
    )

    safe_result = validate_url_for_fetch(
        "https://example.com"
    )

    assert isinstance(
        safe_result,
        dict,
    )


def test_detection_modules_return_structured_results():
    from modules.text_rules import analyze_text_rules
    from modules.call_guardian import assess_call_text
    from modules.phone_check import check_phone
    from modules.email_check import check_email

    text_result = analyze_text_rules(
        "Your account will be blocked. Share the OTP immediately."
    )

    call_result = assess_call_text(
        "I am calling from your bank. Tell me the OTP."
    )

    phone_result = check_phone(
        "+919876543210",
        context="Please share your OTP",
    )

    email_result = check_email(
        "security@example.com",
        subject="Account verification",
        body="Please verify your account.",
    )

    assert isinstance(
        text_result,
        dict,
    )

    assert isinstance(
        call_result,
        dict,
    )

    assert isinstance(
        phone_result,
        dict,
    )

    assert isinstance(
        email_result,
        dict,
    )


def test_application_has_expected_entrypoint():
    import app

    assert hasattr(
        app,
        "main",
    )
