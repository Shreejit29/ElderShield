"""
ElderShield Incoming Call Guardian

Provides a pre-answer safety assessment for suspicious calls.

Current version:
- Works as a web/demo decision layer.
- Does not intercept cellular calls.
- Does not claim that an unknown number is automatically dangerous.

Future Android version:
- This logic can be connected to native incoming-call signals,
  caller reputation services, user reports, and call-time analysis.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# ============================================================
# DATA MODEL
# ============================================================

@dataclass(frozen=True)
class CallAssessment:
    """
    Standardized incoming-call assessment.
    """

    risk: str
    headline: str
    summary: str
    reasons: tuple[str, ...]
    actions: tuple[str, ...]
    should_answer: bool
    should_hang_up: bool
    emergency_action: str


# ============================================================
# DEMO SCENARIOS
# ============================================================

DEMO_SCENARIOS: dict[str, dict[str, Any]] = {

    "unknown": {
        "label": "Unknown caller",
        "risk": "CAUTION",
        "headline": "Unknown caller — be careful",
        "summary": (
            "An unknown number is not automatically a scam, "
            "but you should avoid sharing sensitive information."
        ),
        "reasons": (
            "The caller is not recognized.",
            "The caller's identity has not been independently verified.",
        ),
        "actions": (
            "You may answer if you expect a call.",
            "Do not share OTP, UPI PIN, ATM PIN or passwords.",
            "If the caller creates pressure, end the call.",
            "Verify important claims using an official number.",
        ),
        "should_answer": True,
        "should_hang_up": False,
        "emergency_action": (
            "If the caller asks for money or secrets, stop and verify."
        ),
    },

    "bank_urgency": {
        "label": "Bank account emergency",
        "risk": "HIGH RISK",
        "headline": "Possible bank impersonation scam",
        "summary": (
            "The caller claims there is an urgent banking problem "
            "and wants immediate action."
        ),
        "reasons": (
            "Urgency is being used to pressure the person.",
            "Bank/account problems are commonly used in impersonation scams.",
            "A legitimate bank should not require you to disclose an OTP or PIN."
        ),
        "actions": (
            "Do not share OTP, UPI PIN, ATM PIN or password.",
            "Do not install an app at the caller's request.",
            "Do not transfer money to 'secure' or 'safe' accounts.",
            "End the call if the pressure continues.",
            "Contact the bank using the number on its official website or card."
        ),
        "should_answer": False,
        "should_hang_up": True,
        "emergency_action": (
            "Hang up and contact your bank through an official channel."
        ),
    },

    "digital_arrest": {
        "label": "Police / digital arrest claim",
        "risk": "HIGH RISK",
        "headline": "Possible digital-arrest scam",
        "summary": (
            "The caller claims to be police, an investigator or another "
            "authority and uses threats or legal consequences to create fear."
        ),
        "reasons": (
            "Authority impersonation is a major social-engineering signal.",
            "Threats and fear are being used to reduce careful decision-making.",
            "Fraudsters may demand money or personal information."
        ),
        "actions": (
            "Do not send money because of the caller's threats.",
            "Do not share OTP, PIN or password.",
            "Do not install remote-access software.",
            "Do not keep the call secret from family or trusted people.",
            "End the call and independently contact the claimed organization."
        ),
        "should_answer": False,
        "should_hang_up": True,
        "emergency_action": (
            "End the call. Verify the claim independently."
        ),
    },

    "job_fee": {
        "label": "Job offer with payment request",
        "risk": "HIGH RISK",
        "headline": "Possible job scam",
        "summary": (
            "The caller offers a job but asks for a registration, "
            "security, processing or other payment."
        ),
        "reasons": (
            "Unexpected job offers can be used to obtain advance payments.",
            "A request for money before a promised job is a strong warning sign.",
        ),
        "actions": (
            "Do not pay a registration or security fee because of the call.",
            "Do not share banking credentials or OTP.",
            "Verify the employer through its official website.",
            "Do not install unknown applications sent by the caller."
        ),
        "should_answer": False,
        "should_hang_up": True,
        "emergency_action": (
            "Do not pay. Verify the employer independently."
        ),
    },

    "investment_guarantee": {
        "label": "Guaranteed investment return",
        "risk": "HIGH RISK",
        "headline": "Possible investment scam",
        "summary": (
            "The caller promises unusually high or guaranteed returns "
            "and wants money or account access."
        ),
        "reasons": (
            "Guaranteed high returns are a common investment-scam signal.",
            "Pressure to invest immediately reduces the opportunity to verify.",
        ),
        "actions": (
            "Do not transfer money during the call.",
            "Do not share banking credentials.",
            "Do not install trading or remote-access applications at the caller's request.",
            "Verify the investment company independently.",
        ),
        "should_answer": False,
        "should_hang_up": True,
        "emergency_action": (
            "Stop the transaction and independently verify the investment."
        ),
    },

    "normal": {
        "label": "Expected / ordinary call",
        "risk": "SAFE",
        "headline": "No obvious scam signal",
        "summary": (
            "No significant scam indicator has been supplied for "
            "this demo scenario."
        ),
        "reasons": (
            "No financial demand was identified.",
            "No credential request was identified.",
            "No obvious threat or pressure was identified.",
        ),
        "actions": (
            "You can continue the conversation normally.",
            "Still avoid sharing passwords, OTPs or PINs.",
        ),
        "should_answer": True,
        "should_hang_up": False,
        "emergency_action": (
            "If the conversation changes and becomes suspicious, stop and verify."
        ),
    },
}


# ============================================================
# CORE ASSESSMENT
# ============================================================

def assess_incoming_call(
    scenario: str,
) -> CallAssessment:
    """
    Assess an incoming-call scenario.

    Unknown scenarios fail safely to CAUTION.
    """

    key = (
        str(scenario)
        .strip()
        .lower()
    )

    data = DEMO_SCENARIOS.get(
        key
    )

    if data is None:

        return CallAssessment(
            risk="CAUTION",
            headline="Caller not verified",
            summary=(
                "ElderShield cannot verify this caller from the "
                "available information."
            ),
            reasons=(
                "Caller identity is unknown.",
            ),
            actions=(
                "Do not share OTP, PIN or password.",
                "Do not transfer money because of caller pressure.",
                "Verify important claims independently.",
            ),
            should_answer=False,
            should_hang_up=False,
            emergency_action=(
                "If the caller requests money or secrets, end the call."
            ),
        )

    return CallAssessment(
        risk=str(
            data["risk"]
        ),
        headline=str(
            data["headline"]
        ),
        summary=str(
            data["summary"]
        ),
        reasons=tuple(
            data["reasons"]
        ),
        actions=tuple(
            data["actions"]
        ),
        should_answer=bool(
            data["should_answer"]
        ),
        should_hang_up=bool(
            data["should_hang_up"]
        ),
        emergency_action=str(
            data["emergency_action"]
        ),
    )


# ============================================================
# TEXT-BASED CALL ASSESSMENT
# ============================================================

def assess_call_text(
    text: str,
) -> CallAssessment:
    """
    Perform a lightweight deterministic assessment of a
    caller's description/transcript.

    This is deliberately conservative.

    It is NOT intended to replace the Case Engine or Gemini.
    """

    value = str(
        text or ""
    ).lower().strip()

    if not value:

        return assess_incoming_call(
            "unknown"
        )

    critical_terms = (
        "otp",
        "upi pin",
        "atm pin",
        "password",
        "cvv",
        "transfer money",
        "send money",
        "remote access",
        "screen share",
        "anydesk",
        "teamviewer",
    )

    digital_arrest_terms = (
        "digital arrest",
        "arrest",
        "police",
        "cyber crime",
        "money laundering",
        "court case",
        "warrant",
    )

    bank_terms = (
        "bank",
        "kyc",
        "account blocked",
        "account freeze",
        "account will be closed",
    )

    job_terms = (
        "job",
        "work from home",
        "registration fee",
        "security fee",
        "processing fee",
    )

    investment_terms = (
        "investment",
        "guaranteed return",
        "guaranteed profit",
        "double your money",
        "trading profit",
    )

    urgency_terms = (
        "urgent",
        "immediately",
        "right now",
        "within minutes",
        "do it now",
        "last chance",
    )

    critical_found = [
        term
        for term in critical_terms
        if term in value
    ]

    authority_found = [
        term
        for term in digital_arrest_terms
        if term in value
    ]

    bank_found = [
        term
        for term in bank_terms
        if term in value
    ]

    job_found = [
        term
        for term in job_terms
        if term in value
    ]

    investment_found = [
        term
        for term in investment_terms
        if term in value
    ]

    urgency_found = [
        term
        for term in urgency_terms
        if term in value
    ]

    # --------------------------------------------------------
    # CRITICAL
    # --------------------------------------------------------

    if critical_found:

        reasons = [
            "The caller's description contains a request for sensitive information or a high-risk action.",
        ]

        if urgency_found:

            reasons.append(
                "Urgency is being used to pressure immediate action."
            )

        return CallAssessment(
            risk="CRITICAL",
            headline="Stop — the call contains a dangerous request",
            summary=(
                "The caller appears to be asking for sensitive "
                "information or a financially dangerous action."
            ),
            reasons=tuple(
                reasons
            ),
            actions=(
                "Do not share OTP, UPI PIN, ATM PIN or password.",
                "Do not transfer money.",
                "Do not install remote-access software.",
                "End the call.",
                "Verify the caller through an official channel.",
            ),
            should_answer=False,
            should_hang_up=True,
            emergency_action=(
                "Stop the call and do not provide the requested information."
            ),
        )

    # --------------------------------------------------------
    # DIGITAL ARREST / AUTHORITY
    # --------------------------------------------------------

    if authority_found and (
        urgency_found
        or bank_found
        or "money" in value
        or "payment" in value
    ):

        return assess_incoming_call(
            "digital_arrest"
        )

    # --------------------------------------------------------
    # BANK + URGENCY
    # --------------------------------------------------------

    if bank_found and urgency_found:

        return assess_incoming_call(
            "bank_urgency"
        )

    # --------------------------------------------------------
    # JOB SCAM
    # --------------------------------------------------------

    if job_found and (
        "fee" in value
        or "pay" in value
        or "payment" in value
        or "money" in value
    ):

        return assess_incoming_call(
            "job_fee"
        )

    # --------------------------------------------------------
    # INVESTMENT SCAM
    # --------------------------------------------------------

    if investment_found and (
        "guaranteed" in value
        or "profit" in value
        or "money" in value
        or "pay" in value
        or urgency_found
    ):

        return assess_incoming_call(
            "investment_guarantee"
        )

    # --------------------------------------------------------
    # URGENCY WITHOUT CRITICAL ACTION
    # --------------------------------------------------------

    if urgency_found:

        return CallAssessment(
            risk="CAUTION",
            headline="Caller is creating urgency",
            summary=(
                "The caller appears to be pressuring you to act "
                "quickly. Take time to verify the claim."
            ),
            reasons=(
                "Urgency can be used in social-engineering scams.",
            ),
            actions=(
                "Do not make a financial decision during the call.",
                "Do not share OTP, PIN or password.",
                "Verify the caller independently.",
            ),
            should_answer=True,
            should_hang_up=False,
            emergency_action=(
                "Slow down. Verify before taking any action."
            ),
        )

    # --------------------------------------------------------
    # DEFAULT
    # --------------------------------------------------------

    return assess_incoming_call(
        "normal"
    )


# ============================================================
# SERIALIZATION
# ============================================================

def assessment_to_dict(
    assessment: CallAssessment,
) -> dict[str, Any]:
    """
    Convert CallAssessment into a JSON-friendly dictionary.
    """

    return {
        "risk": assessment.risk,
        "headline": assessment.headline,
        "summary": assessment.summary,
        "reasons": list(
            assessment.reasons
        ),
        "actions": list(
            assessment.actions
        ),
        "should_answer": assessment.should_answer,
        "should_hang_up": assessment.should_hang_up,
        "emergency_action": assessment.emergency_action,
    }
