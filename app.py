"""
ElderShield
AI-assisted anti-phishing and scam safety assistant.

Streamlit entry point.

Important safety boundaries:
- User evidence is treated as untrusted content.
- ElderShield never asks for OTPs, PINs, passwords, or card credentials.
- URLs are analyzed locally before any optional future network access.
- Gemini failures must never become a SAFE verdict.
- A normal web app cannot intercept cellular calls or other apps in real time.
"""

from __future__ import annotations

import json
from typing import Any

import streamlit as st

from modules.case_engine import analyze_case
from modules.call_guardian import assess_call_text
from modules.gemini_audio import analyze_audio
from modules.gemini_screen import analyze_screen
from modules.health_check import run_health_check
from modules.input_guard import validate_image
from modules.intervention import get_intervention
from modules.report import (
    normalize_risk,
    report_from_case,
    report_to_markdown,
    report_to_text,
)
from modules.url_analyzer import analyze_url


# ============================================================
# APPLICATION SETTINGS
# ============================================================

APP_NAME = "ElderShield"
APP_VERSION = "5.0.0"

st.set_page_config(
    page_title="ElderShield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# SESSION STATE
# ============================================================

if "privacy_acknowledged" not in st.session_state:
    st.session_state.privacy_acknowledged = False

if "history" not in st.session_state:
    st.session_state.history = []

if "last_case" not in st.session_state:
    st.session_state.last_case = None


# ============================================================
# HELPERS
# ============================================================

RISK_EMOJI = {
    "SAFE": "🟢",
    "CAUTION": "🟡",
    "HIGH": "🟠",
    "CRITICAL": "🔴",
    "UNKNOWN": "⚪",
}


def risk_label(risk: str) -> str:
    """Return a safe normalized risk label."""
    try:
        return normalize_risk(risk)
    except Exception:
        value = str(risk or "UNKNOWN").upper()

        if value in {
            "SAFE",
            "CAUTION",
            "HIGH",
            "CRITICAL",
            "UNKNOWN",
        }:
            return value

        return "UNKNOWN"


def show_risk(risk: str) -> None:
    """Display a prominent risk result."""
    level = risk_label(risk)
    emoji = RISK_EMOJI.get(level, "⚪")

    st.subheader(f"{emoji} {level}")

    if level == "SAFE":
        st.success(
            "No strong scam indicators were detected. "
            "Still verify important requests through official channels."
        )

    elif level == "CAUTION":
        st.warning(
            "Some warning signs were detected. "
            "Pause and verify before taking action."
        )

    elif level == "HIGH":
        st.warning(
            "This looks suspicious. Do not provide sensitive information "
            "or make payments until independently verified."
        )

    elif level == "CRITICAL":
        st.error(
            "STOP. This interaction contains a critical safety signal. "
            "Do not share OTPs, PINs, passwords, bank credentials, "
            "or approve payments."
        )

    else:
        st.info(
            "ElderShield could not establish a reliable safety verdict. "
            "Treat the content cautiously and verify independently."
        )


def display_list(
    title: str,
    items: Any,
) -> None:
    """Display a compact list when values are available."""
    if not items:
        return

    st.markdown(f"**{title}**")

    for item in items:
        text = str(item).strip()

        if text:
            st.markdown(f"- {text}")


def save_case(case: dict[str, Any]) -> None:
    """
    Save only privacy-conscious case information.

    Raw messages, images, and audio are intentionally not stored.
    """

    risk = risk_label(
        case.get("risk", "UNKNOWN")
    )

    history_item = {
        "risk": risk,
        "summary": str(
            case.get("summary", "")
        )[:500],
        "categories": case.get(
            "categories",
            [],
        ),
        "channels": case.get(
            "channels",
            [],
        ),
    }

    st.session_state.history.insert(
        0,
        history_item,
    )

    st.session_state.history = (
        st.session_state.history[:20]
    )

    st.session_state.last_case = case


def display_case(case: dict[str, Any]) -> None:
    """Display a standardized ElderShield case result."""

    if not isinstance(case, dict):
        st.error(
            "ElderShield received an invalid analysis result."
        )
        return

    risk = risk_label(
        case.get("risk", "UNKNOWN")
    )

    show_risk(risk)

    summary = case.get("summary")

    if summary:
        st.markdown(
            f"### What ElderShield found\n\n{summary}"
        )

    display_list(
        "Why this was flagged",
        case.get("reasons", []),
    )

    display_list(
        "Dangerous actions detected",
        case.get("dangerous_actions", []),
    )

    display_list(
        "Recommended actions",
        case.get("actions", []),
    )

    display_list(
        "Scam categories",
        case.get("categories", []),
    )

    display_list(
        "Detected signal groups",
        case.get("signal_groups", []),
    )

    channels = case.get("channels", [])

    if channels:
        st.caption(
            "Evidence channels: "
            + ", ".join(
                str(channel)
                for channel in channels
            )
        )

    confidence = case.get(
        "confidence_note"
    )

    if confidence:
        st.caption(
            f"ℹ️ {confidence}"
        )


def safe_case_from_text(
    text: str,
    channel: str,
) -> dict[str, Any]:
    """
    Analyze text through the central case engine.

    Any unexpected failure becomes UNKNOWN rather than SAFE.
    """

    try:
        return analyze_case(
            message=text,
            channel=channel,
        )
    except TypeError:
        # Compatibility with earlier case-engine signatures.
        try:
            return analyze_case(
                message=text,
            )
        except Exception as exc:
            return {
                "risk": "UNKNOWN",
                "summary": (
                    "ElderShield could not complete the analysis."
                ),
                "reasons": [
                    "The analysis engine returned an error."
                ],
                "actions": [
                    "Do not take financial or credential-related action.",
                    "Verify through an official channel.",
                ],
                "error": str(exc),
                "channels": [channel],
            }

    except Exception as exc:
        return {
            "risk": "UNKNOWN",
            "summary": (
                "ElderShield could not complete the analysis."
            ),
            "reasons": [
                "The analysis engine returned an error."
            ],
            "actions": [
                "Do not take financial or credential-related action.",
                "Verify through an official channel.",
            ],
            "error": str(exc),
            "channels": [channel],
        }


def display_report(case: dict[str, Any]) -> None:
    """Offer a privacy-conscious report without raw evidence."""

    try:
        report = report_from_case(case)

        with st.expander(
            "📋 View safety report"
        ):
            st.markdown(
                report_to_markdown(report)
            )

            st.download_button(
                label="Download text report",
                data=report_to_text(report),
                file_name="eldershield_report.txt",
                mime="text/plain",
            )

    except Exception:
        # Reporting must never break the main safety result.
        return


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ ElderShield")

st.markdown(
    """
### Show ElderShield what you are seeing, and it tells you what to do.

**Stop → Check → Protect**

ElderShield is a safety aid for suspicious messages, screens,
calls and links. It is especially designed around common
scam patterns affecting people in India.
"""
)

st.caption(
    f"ElderShield v{APP_VERSION} • "
    "Open-source social-benefit project"
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header("🛡️ ElderShield")

    st.markdown(
        """
**Simple rule:**

> Stop first.  
> Check second.  
> Pay or share nothing until verified.
        """
    )

    st.divider()

    st.subheader("🔐 Privacy")

    st.caption(
        "Never enter an actual OTP, UPI PIN, ATM PIN, "
        "password or full card credentials into ElderShield."
    )

    st.divider()

    st.subheader("System")

    try:
        health = run_health_check()

        if health.get("ok"):
            st.success(
                "Local safety modules: OK"
            )
        else:
            st.warning(
                "Some local modules need attention."
            )

    except Exception:
        st.warning(
            "Health check unavailable."
        )

    st.divider()

    st.caption(
        "ElderShield is a safety aid, not a guarantee."
    )


# ============================================================
# PRIVACY ACKNOWLEDGEMENT
# ============================================================

if not st.session_state.privacy_acknowledged:

    st.warning(
        """
### Before using ElderShield

ElderShield analyzes content that you provide.

Do **not** intentionally submit:
- OTPs
- UPI PINs
- ATM PINs
- passwords
- full card numbers
- CVV
- other highly sensitive credentials

Treat screenshots, messages, links and audio as untrusted evidence.
        """
    )

    acknowledged = st.checkbox(
        "I understand and will not intentionally submit passwords, PINs or OTPs."
    )

    if st.button(
        "Continue to ElderShield",
        type="primary",
        disabled=not acknowledged,
    ):
        st.session_state.privacy_acknowledged = True
        st.rerun()

    st.stop()


# ============================================================
# MAIN TABS
# ============================================================

tabs = st.tabs(
    [
        "🖥️ Screen Guardian",
        "💬 Message Guardian",
        "📞 Call Guardian",
        "🔗 URL Guardian",
    ]
)


# ============================================================
# SCREEN GUARDIAN
# ============================================================

with tabs[0]:

    st.header("🖥️ Screen Guardian")

    st.write(
        "Upload a screenshot of a suspicious message, "
        "website, payment request, bank notice or pop-up."
    )

    st.info(
        "Before uploading, hide OTPs, PINs, passwords and "
        "full payment-card credentials."
    )

    image_file = st.file_uploader(
        "Upload screenshot",
        type=[
            "png",
            "jpg",
            "jpeg",
            "webp",
        ],
        key="screen_upload",
    )

    if image_file is not None:

        image_bytes = image_file.getvalue()

        validation = validate_image(
            image_bytes
        )

        if not validation.get(
            "valid",
            False,
        ):
            st.error(
                validation.get(
                    "error",
                    "Invalid image.",
                )
            )
        else:

            st.image(
                image_bytes,
                caption="Submitted evidence",
                use_container_width=True,
            )

            if st.button(
                "🔍 Check this screen",
                type="primary",
                key="analyze_screen",
            ):

                with st.spinner(
                    "ElderShield is checking the screen..."
                ):

                    try:
                        ai_result = analyze_screen(
                            image_bytes
                        )

                        # Feed AI evidence into the central engine
                        # where possible.
                        case = safe_case_from_text(
                            json.dumps(
                                ai_result,
                                ensure_ascii=False,
                            ),
                            "screen",
                        )

                        # Preserve AI evidence.
                        case["ai_evidence"] = ai_result

                    except Exception:
                        case = {
                            "risk": "UNKNOWN",
                            "summary": (
                                "The screen could not be reliably analyzed."
                            ),
                            "reasons": [
                                "AI analysis was unavailable."
                            ],
                            "actions": [
                                "Do not click links or approve payments.",
                                "Verify the request independently.",
                            ],
                            "channels": ["screen"],
                        }

                save_case(case)
                display_case(case)
                display_report(case)


# ============================================================
# MESSAGE GUARDIAN
# ============================================================

with tabs[1]:

    st.header("💬 Message Guardian")

    st.write(
        "Paste a suspicious SMS, WhatsApp message, email text, "
        "or other message here."
    )

    st.info(
        "Use synthetic test messages whenever possible. "
        "Never paste an actual OTP, PIN or password."
    )

    message = st.text_area(
        "Paste message",
        height=220,
        placeholder=(
            "Example: Your account will be blocked today. "
            "Please verify immediately..."
        ),
        key="message_text",
    )

    if st.button(
        "🔍 Check message",
        type="primary",
        key="analyze_message",
    ):

        if not message.strip():

            st.warning(
                "Please enter a message first."
            )

        else:

            with st.spinner(
                "ElderShield is checking the message..."
            ):

                case = safe_case_from_text(
                    message.strip(),
                    "message",
                )

            save_case(case)
            display_case(case)
            display_report(case)


# ============================================================
# CALL GUARDIAN
# ============================================================

with tabs[2]:

    st.header("📞 Incoming Call Guardian")

    st.warning(
        """
### Should I answer?

A suspicious caller can start social engineering before
asking for money or credentials.

An unknown number alone does **not** mean the call is a scam.
The warning becomes stronger when the caller uses threats,
urgency, impersonation or asks for sensitive information.
        """
    )

    st.subheader("Demo scenarios")

    scenario = st.selectbox(
        "Choose a call scenario",
        [
            "Unknown caller",
            "Bank/KYC urgency",
            "Digital arrest",
            "Job fee request",
            "Investment guarantee",
            "Normal call",
        ],
    )

    scenario_text = {
        "Unknown caller": (
            "An unknown caller is calling. "
            "No claim or request has been provided yet."
        ),
        "Bank/KYC urgency": (
            "I am calling from your bank. "
            "Your account will be blocked today. "
            "Give me the OTP immediately to complete KYC."
        ),
        "Digital arrest": (
            "You are involved in a criminal case. "
            "Stay on the video call and follow our instructions "
            "or you will be arrested."
        ),
        "Job fee request": (
            "Congratulations, you have been selected for the job. "
            "Pay the registration and security fee immediately."
        ),
        "Investment guarantee": (
            "Our investment plan guarantees very high returns. "
            "Transfer the money today to secure your guaranteed profit."
        ),
        "Normal call": (
            "Hello, I am calling to confirm our meeting tomorrow."
        ),
    }

    if st.button(
        "📞 Assess incoming call",
        type="primary",
        key="assess_call",
    ):

        text = scenario_text[
            scenario
        ]

        try:
            result = assess_call_text(
                text
            )

            case = safe_case_from_text(
                text,
                "call",
            )

            # Preserve the more severe deterministic call result.
            call_risk = risk_label(
                result.get(
                    "risk",
                    "UNKNOWN",
                )
            )

            case_risk = risk_label(
                case.get(
                    "risk",
                    "UNKNOWN",
                )
            )

            priority = {
                "SAFE": 0,
                "UNKNOWN": 1,
                "CAUTION": 2,
                "HIGH": 3,
                "CRITICAL": 4,
            }

            if priority.get(
                call_risk,
                1,
            ) > priority.get(
                case_risk,
                1,
            ):
                case["risk"] = call_risk

            case["call_evidence"] = result

        except Exception as exc:

            case = {
                "risk": "UNKNOWN",
                "summary": (
                    "The call could not be reliably assessed."
                ),
                "reasons": [
                    "Call analysis was unavailable."
                ],
                "actions": [
                    "Do not share credentials or approve payments.",
                    "Verify the caller independently.",
                ],
                "channels": ["call"],
                "error": str(exc),
            }

        save_case(case)
        display_case(case)
        display_report(case)

    st.divider()

    st.subheader("✍️ Analyze what the caller said")

    call_text = st.text_area(
        "Caller statement",
        height=180,
        placeholder=(
            "Example: I am from the bank. "
            "Your account has a problem..."
        ),
        key="call_text",
    )

    if st.button(
        "🔍 Check caller statement",
        key="analyze_call_text",
    ):

        if not call_text.strip():

            st.warning(
                "Please enter what the caller said."
            )

        else:

            with st.spinner(
                "Checking the caller statement..."
            ):

                try:
                    call_result = assess_call_text(
                        call_text.strip()
                    )

                    case = safe_case_from_text(
                        call_text.strip(),
                        "call",
                    )

                    case["call_evidence"] = (
                        call_result
                    )

                except Exception:

                    case = {
                        "risk": "UNKNOWN",
                        "summary": (
                            "The caller statement could not be "
                            "reliably assessed."
                        ),
                        "reasons": [
                            "Analysis was unavailable."
                        ],
                        "actions": [
                            "Do not share sensitive information.",
                            "Verify independently.",
                        ],
                        "channels": ["call"],
                    }

            save_case(case)
            display_case(case)
            display_report(case)


# ============================================================
# URL GUARDIAN
# ============================================================

with tabs[3]:

    st.header("🔗 URL Guardian")

    st.write(
        "Paste a link here before opening it."
    )

    st.warning(
        "Do not open the suspicious link first. "
        "Paste it directly into ElderShield."
    )

    url = st.text_input(
        "Suspicious URL",
        placeholder="https://example.com/verify",
        key="url_text",
    )

    if st.button(
        "🔍 Check URL",
        type="primary",
        key="analyze_url",
    ):

        if not url.strip():

            st.warning(
                "Please enter a URL first."
            )

        else:

            with st.spinner(
                "Checking URL structure..."
            ):

                try:

                    url_result = analyze_url(
                        url.strip()
                    )

                    case = safe_case_from_text(
                        url.strip(),
                        "url",
                    )

                    case["url_analysis"] = (
                        url_result
                    )

                    # URL analysis is deterministic and should
                    # influence the final verdict when severe.
                    url_risk = risk_label(
                        url_result.get(
                            "risk",
                            "UNKNOWN",
                        )
                    )

                    case_risk = risk_label(
                        case.get(
                            "risk",
                            "UNKNOWN",
                        )
                    )

                    priority = {
                        "SAFE": 0,
                        "UNKNOWN": 1,
                        "CAUTION": 2,
                        "HIGH": 3,
                        "CRITICAL": 4,
                    }

                    if priority.get(
                        url_risk,
                        1,
                    ) > priority.get(
                        case_risk,
                        1,
                    ):
                        case["risk"] = url_risk

                except Exception:

                    case = {
                        "risk": "UNKNOWN",
                        "summary": (
                            "The URL could not be reliably analyzed."
                        ),
                        "reasons": [
                            "URL analysis failed."
                        ],
                        "actions": [
                            "Do not open the link.",
                            "Verify the website through an official source.",
                        ],
                        "channels": ["url"],
                    }

            save_case(case)
            display_case(case)
            display_report(case)


# ============================================================
# HISTORY
# ============================================================

st.divider()

st.header("🧾 Recent checks")

if not st.session_state.history:

    st.caption(
        "No previous checks in this browser session."
    )

else:

    for index, item in enumerate(
        st.session_state.history
    ):

        risk = risk_label(
            item.get(
                "risk",
                "UNKNOWN",
            )
        )

        emoji = RISK_EMOJI.get(
            risk,
            "⚪",
        )

        with st.expander(
            f"{emoji} {risk} — "
            f"{item.get('summary', 'Safety check')[:100]}"
        ):

            if item.get("summary"):
                st.write(
                    item["summary"]
                )

            if item.get("categories"):
                st.caption(
                    "Categories: "
                    + ", ".join(
                        str(x)
                        for x in item["categories"]
                    )
                )

            if item.get("channels"):
                st.caption(
                    "Channel: "
                    + ", ".join(
                        str(x)
                        for x in item["channels"]
                    )
                )


# ============================================================
# SAFETY FOOTER
# ============================================================

st.divider()

st.markdown(
    """
### 🛡️ ElderShield safety rules

**Never share:**
- OTP
- UPI PIN
- ATM PIN
- Password
- CVV
- Full card credentials

**Never allow an unexpected caller to:**
- install remote-access software
- control your screen
- move money
- approve a payment
- "verify" your bank account using an OTP

**When money or credentials may already have been shared:**
stop further interaction immediately and contact the relevant
bank/service through its official channel.

ElderShield does not guarantee safety and does not replace
banks, law enforcement, cybersecurity professionals, or official
support channels.

The current Streamlit version cannot silently monitor phone calls,
WhatsApp, other apps, or stop a transaction. Those capabilities
would require a future native platform implementation.
"""
)

st.caption(
    "ElderShield • Open-source • Built for social benefit"
)
