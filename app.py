import io
import json
import os
from datetime import datetime

import streamlit as st
from PIL import Image

from modules.case_engine import analyze_case
from modules.gemini_screen import analyze_screen
from modules.gemini_audio import analyze_audio
from modules.intervention import get_intervention
from modules.url_analyzer import analyze_url
from modules.official_verify import verify_organization
from modules.input_guard import validate_image
from modules.knowledge import get_scam_category


# ============================================================
# ELDER SHIELD
# Main Streamlit Application
# ============================================================

APP_NAME = "ElderShield"
APP_VERSION = "5.0.0"


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="ElderShield — Stop. Check. Protect.",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# SESSION STATE
# ============================================================

if "history" not in st.session_state:
    st.session_state.history = []

if "privacy_accepted" not in st.session_state:
    st.session_state.privacy_accepted = False

if "language" not in st.session_state:
    st.session_state.language = "English"


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>
    .main-title {
        font-size: 42px;
        font-weight: 800;
        margin-bottom: 0;
    }

    .subtitle {
        font-size: 20px;
        margin-top: 0;
        margin-bottom: 20px;
    }

    .risk-box {
        padding: 24px;
        border-radius: 16px;
        margin: 15px 0;
        border: 2px solid rgba(128,128,128,0.25);
    }

    .critical-text {
        font-size: 30px;
        font-weight: 800;
    }

    .big-action {
        font-size: 24px;
        font-weight: 700;
    }

    .elder-button {
        min-height: 55px;
        font-size: 20px !important;
    }

    .small-note {
        font-size: 14px;
        opacity: 0.75;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ ElderShield</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="subtitle">Stop. Check. Protect.</div>',
    unsafe_allow_html=True,
)

st.write(
    "An AI-assisted safety tool designed to help identify scams, "
    "phishing, impersonation and financial-fraud attempts."
)

st.info(
    "⚠️ ElderShield is a safety assistant, not a guarantee. "
    "When something involves money, passwords, OTPs or PINs, "
    "verify independently before taking action."
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header("🛡️ ElderShield")

    st.caption(f"Version {APP_VERSION}")

    st.divider()

    language = st.selectbox(
        "🌐 Language",
        ["English", "हिन्दी", "मराठी"],
        index=["English", "हिन्दी", "मराठी"].index(
            st.session_state.language
        ),
    )

    st.session_state.language = language

    st.divider()

    st.subheader("Safety Rule")

    st.warning(
        "Never share your OTP, UPI PIN, ATM PIN, password "
        "or full card details with someone who contacts you."
    )

    st.divider()

    st.subheader("Demo")

    st.caption(
        "The Incoming Call Guard currently uses Demo Mode. "
        "Automatic phone-call integration will be developed "
        "later as a native Android component."
    )


# ============================================================
# PRIVACY ACKNOWLEDGEMENT
# ============================================================

if not st.session_state.privacy_accepted:

    st.subheader("🔐 Before you use ElderShield")

    st.write(
        "Please do not upload or enter passwords, OTPs, UPI PINs, "
        "ATM PINs or complete payment-card credentials."
    )

    st.write(
        "Screenshots, messages and audio may contain personal "
        "information. Only provide information that is necessary "
        "for checking a suspected scam."
    )

    accepted = st.checkbox(
        "I understand and want to continue."
    )

    if st.button(
        "Continue to ElderShield",
        type="primary",
        use_container_width=True,
    ):
        if accepted:
            st.session_state.privacy_accepted = True
            st.rerun()
        else:
            st.error(
                "Please confirm that you understand the privacy notice."
            )

    st.stop()


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def add_history(result, source):
    """Store a minimal analysis result in the current session."""

    entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "risk": result.get("risk", "UNKNOWN"),
        "summary": result.get("summary", ""),
    }

    st.session_state.history.insert(0, entry)

    # Keep session history small.
    st.session_state.history = st.session_state.history[:20]


def risk_emoji(risk):
    """Return an emoji appropriate for a risk level."""

    mapping = {
        "SAFE": "🟢",
        "CAUTION": "🟡",
        "HIGH RISK": "🟠",
        "CRITICAL": "🔴",
        "UNKNOWN": "⚪",
    }

    return mapping.get(risk.upper(), "⚪")


def display_result(result):
    """Display a standardized ElderShield result."""

    risk = str(result.get("risk", "UNKNOWN")).upper()

    summary = result.get(
        "summary",
        "ElderShield could not produce a detailed explanation.",
    )

    reasons = result.get("reasons", [])
    actions = result.get("actions", [])

    st.divider()

    st.markdown(
        f"## {risk_emoji(risk)} {risk}"
    )

    if risk == "CRITICAL":
        st.error(
            f"### 🛑 STOP\n\n{summary}"
        )

    elif risk == "HIGH RISK":
        st.error(
            f"### ⚠️ Do not continue\n\n{summary}"
        )

    elif risk == "CAUTION":
        st.warning(
            f"### ⚠️ Be careful\n\n{summary}"
        )

    elif risk == "SAFE":
        st.success(
            f"### ✅ No strong scam signal detected\n\n{summary}"
        )

    else:
        st.info(summary)

    if reasons:

        st.subheader("Why ElderShield says this")

        for reason in reasons:
            st.write(f"• {reason}")

    if actions:

        st.subheader("What should you do?")

        for index, action in enumerate(actions, start=1):
            st.markdown(
                f"**{index}. {action}**"
            )

    # Critical safety reminder.
    if risk in {"CRITICAL", "HIGH RISK"}:

        st.error(
            "🔐 Never share OTP, UPI PIN, ATM PIN, password "
            "or full card credentials."
        )


def safe_result_from_case(evidence):
    """
    Run the ElderShield case engine.

    The case engine is deliberately isolated from the UI so that
    the same logic can later be reused by the Android application.
    """

    try:
        result = analyze_case(evidence)

        if not isinstance(result, dict):
            raise ValueError("Case engine returned an invalid result.")

        return result

    except Exception as exc:

        return {
            "risk": "UNKNOWN",
            "summary": (
                "ElderShield could not complete the analysis. "
                "Do not take financial action until you verify "
                "the situation independently."
            ),
            "reasons": [
                f"Analysis error: {type(exc).__name__}"
            ],
            "actions": [
                "Do not click links or make payments.",
                "Contact the organization using a trusted channel.",
            ],
        }


# ============================================================
# MAIN TABS
# ============================================================

tab_screen, tab_message, tab_call, tab_url = st.tabs(
    [
        "📸 Check a Screen",
        "📝 Check a Message",
        "☎️ Check a Call",
        "🔗 Check a Link",
    ]
)


# ============================================================
# SCREEN GUARDIAN
# ============================================================

with tab_screen:

    st.header("📸 Screen Guardian")

    st.write(
        "Show ElderShield what you are seeing. "
        "It can examine a screenshot for scam indicators."
    )

    st.warning(
        "Do not upload screenshots containing passwords, "
        "OTP codes, UPI PINs or other secrets."
    )

    image_source = st.radio(
        "Choose how to provide the screen:",
        [
            "Upload screenshot",
            "Use camera",
        ],
        horizontal=True,
    )

    uploaded_image = None

    if image_source == "Upload screenshot":

        uploaded_image = st.file_uploader(
            "Upload a screenshot",
            type=["png", "jpg", "jpeg", "webp"],
        )

    else:

        uploaded_image = st.camera_input(
            "Take a picture of the suspicious screen"
        )

    if uploaded_image:

        try:

            image_bytes = uploaded_image.getvalue()

            valid, message = validate_image(
                image_bytes,
                uploaded_image.type,
            )

            if not valid:
                st.error(message)
                st.stop()

            image = Image.open(
                io.BytesIO(image_bytes)
            )

            st.image(
                image,
                caption="Screen provided to ElderShield",
                use_container_width=True,
            )

            if st.button(
                "🔍 Analyze this screen",
                type="primary",
                use_container_width=True,
            ):

                with st.spinner(
                    "ElderShield is checking the screen..."
                ):

                    screen_result = analyze_screen(
                        image_bytes=image_bytes,
                        mime_type=uploaded_image.type,
                    )

                if not isinstance(screen_result, dict):

                    screen_result = {
                        "risk": "UNKNOWN",
                        "summary": "Unable to analyze the screen.",
                        "reasons": [],
                        "actions": [
                            "Do not take financial action until verified."
                        ],
                    }

                # Combine Gemini evidence with deterministic case engine.
                evidence = {
                    "channel": "screen",
                    "screen_analysis": screen_result,
                }

                final_result = safe_result_from_case(
                    evidence
                )

                display_result(final_result)

                add_history(
                    final_result,
                    "Screen",
                )

        except Exception as exc:

            st.error(
                "ElderShield could not process this image."
            )

            st.caption(
                f"Technical detail: {type(exc).__name__}"
            )


# ============================================================
# MESSAGE GUARDIAN
# ============================================================

with tab_message:

    st.header("📝 Message Guardian")

    st.write(
        "Paste a suspicious SMS, WhatsApp message, email or "
        "social-media message."
    )

    message_text = st.text_area(
        "Suspicious message",
        height=220,
        placeholder=(
            "Example:\n"
            "Your bank account will be blocked today. "
            "Click this link to complete KYC..."
        ),
    )

    if st.button(
        "🔍 Check this message",
        type="primary",
        use_container_width=True,
    ):

        if not message_text.strip():

            st.warning(
                "Please enter the message you want to check."
            )

        else:

            evidence = {
                "channel": "message",
                "message_text": message_text,
            }

            with st.spinner(
                "ElderShield is checking the message..."
            ):

                result = safe_result_from_case(
                    evidence
                )

            display_result(result)

            add_history(
                result,
                "Message",
            )


# ============================================================
# CALL GUARDIAN
# ============================================================

with tab_call:

    st.header("☎️ Call Guardian")

    st.warning(
        "DEMO MODE — This simulates how future ElderShield "
        "Android call protection can work. A normal web app "
        "cannot automatically access cellular call audio."
    )

    call_mode = st.radio(
        "Choose demo input:",
        [
            "Describe the call",
            "Provide call audio",
        ],
        horizontal=True,
    )

    if call_mode == "Describe the call":

        call_description = st.text_area(
            "What is the caller saying?",
            height=220,
            placeholder=(
                "Example:\n"
                "The caller says they are from my bank and "
                "asks me to transfer money to a safe account."
            ),
        )

        if st.button(
            "☎️ Analyze Call",
            type="primary",
            use_container_width=True,
        ):

            if not call_description.strip():

                st.warning(
                    "Please describe what the caller is saying."
                )

            else:

                evidence = {
                    "channel": "call",
                    "call_description": call_description,
                }

                with st.spinner(
                    "ElderShield is analyzing the call..."
                ):

                    result = safe_result_from_case(
                        evidence
                    )

                display_result(result)

                add_history(
                    result,
                    "Call",
                )

    else:

        st.write(
            "For the demo, provide an audio recording only where "
            "recording and processing it is lawful and appropriate."
        )

        audio_file = st.file_uploader(
            "Upload call audio",
            type=[
                "wav",
                "mp3",
                "m4a",
                "ogg",
            ],
        )

        if audio_file:

            st.audio(
                audio_file,
            )

            if st.button(
                "🎙️ Analyze Call Audio",
                type="primary",
                use_container_width=True,
            ):

                audio_bytes = audio_file.getvalue()

                with st.spinner(
                    "ElderShield is analyzing the call audio..."
                ):

                    audio_result = analyze_audio(
                        audio_bytes=audio_bytes,
                        mime_type=audio_file.type,
                    )

                evidence = {
                    "channel": "call",
                    "audio_analysis": audio_result,
                }

                result = safe_result_from_case(
                    evidence
                )

                display_result(result)

                add_history(
                    result,
                    "Call audio",
                )


# ============================================================
# URL GUARDIAN
# ============================================================

with tab_url:

    st.header("🔗 Link Guardian")

    st.write(
        "Paste a suspicious website address. ElderShield "
        "checks its structure and known organization-domain signals."
    )

    url = st.text_input(
        "Website URL",
        placeholder="https://example.com",
    )

    if st.button(
        "🔍 Check Link",
        type="primary",
        use_container_width=True,
    ):

        if not url.strip():

            st.warning(
                "Please enter a URL."
            )

        else:

            with st.spinner(
                "ElderShield is checking the link..."
            ):

                url_result = analyze_url(
                    url.strip()
                )

            st.subheader("URL analysis")

            if isinstance(url_result, dict):

                risk = str(
                    url_result.get(
                        "risk",
                        "UNKNOWN",
                    )
                ).upper()

                st.write(
                    f"### {risk_emoji(risk)} {risk}"
                )

                if url_result.get("reasons"):

                    for reason in url_result["reasons"]:
                        st.write(
                            f"• {reason}"
                        )

                domain = url_result.get(
                    "domain"
                )

                organization = url_result.get(
                    "organization"
                )

                if domain:

                    st.write(
                        f"**Domain detected:** `{domain}`"
                    )

                if organization:

                    verification = verify_organization(
                        organization,
                        domain,
                    )

                    st.subheader(
                        "🏦 Organization verification"
                    )

                    st.info(
                        verification.get(
                            "message",
                            "Verification information unavailable.",
                        )
                    )

            evidence = {
                "channel": "url",
                "url": url.strip(),
                "url_analysis": url_result,
            }

            result = safe_result_from_case(
                evidence
            )

            display_result(result)

            add_history(
                result,
                "URL",
            )


# ============================================================
# CASE HISTORY
# ============================================================

st.divider()

st.header("🧾 Recent Checks")

if not st.session_state.history:

    st.caption(
        "No checks have been performed in this session."
    )

else:

    for item in st.session_state.history:

        risk = item["risk"]

        with st.expander(
            f"{risk_emoji(risk)} {risk} — "
            f"{item['source']} — {item['time']}"
        ):

            st.write(
                item["summary"]
            )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "🛡️ ElderShield — Open-source safety project"
)

st.caption(
    "ElderShield provides safety guidance and cannot guarantee "
    "that a message, call, website or payment request is safe."
)

st.caption(
    "Never share OTPs, UPI PINs, ATM PINs, passwords or complete "
    "card credentials with a caller or message sender."
)
