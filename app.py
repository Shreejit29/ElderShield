"""
ElderShield
AI-assisted anti-phishing and scam safety assistant.

Streamlit application entry point.

Safety principles:
- Deterministic safety rules remain functional without Gemini.
- Gemini is an additional evidence layer, not the only detector.
- User-submitted content is treated as untrusted evidence.
- ElderShield never asks users for OTPs, PINs, passwords, CVV,
  or full payment-card credentials.
- The current web version cannot intercept phone calls or other apps.
"""

from __future__ import annotations

import json
from typing import Any

import streamlit as st

from modules.call_guardian import assess_call_text
from modules.health_check import run_health_check
from modules.input_guard import validate_image
from modules.report import (
    normalize_risk,
    report_from_case,
    report_to_markdown,
    report_to_text,
)
from modules.text_rules import analyze_text_rules
from modules.url_analyzer import analyze_url

# Optional AI modules.
# Import failures must not prevent the deterministic application
# from starting.
try:
    from modules.gemini_screen import analyze_screen
except Exception:
    analyze_screen = None

try:
    from modules.gemini_audio import analyze_audio
except Exception:
    analyze_audio = None


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
# RISK HELPERS
# ============================================================

RISK_ORDER = {
    "SAFE": 0,
    "UNKNOWN": 1,
    "CAUTION": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

RISK_EMOJI = {
    "SAFE": "🟢",
    "UNKNOWN": "⚪",
    "CAUTION": "🟡",
    "HIGH": "🟠",
    "CRITICAL": "🔴",
}


def clean_risk(value: Any) -> str:
    """Normalize a risk value safely."""

    try:
        result = normalize_risk(value)
    except Exception:
        result = str(value or "UNKNOWN").upper()

    if result not in RISK_ORDER:
        return "UNKNOWN"

    return result


def highest_risk(*values: Any) -> str:
    """Return the most severe valid risk."""

    risks = [
        clean_risk(value)
        for value in values
    ]

    return max(
        risks,
        key=lambda risk: RISK_ORDER[risk],
    )


def merge_unique(
    *collections: Any,
) -> list[str]:
    """Merge string collections without duplicates."""

    output: list[str] = []

    for collection in collections:
        if not collection:
            continue

        if isinstance(
            collection,
            str,
        ):
            collection = [collection]

        try:
            iterator = collection
        except Exception:
            continue

        for item in iterator:
            value = str(item).strip()

            if value and value not in output:
                output.append(value)

    return output


# ============================================================
# RESULT BUILDERS
# ============================================================

def emergency_actions() -> list[str]:
    return [
        "Stop the interaction before taking further action.",
        "Do not share OTPs, PINs, passwords or card credentials.",
        "Do not install remote-access software.",
        "Do not approve or transfer money.",
        "Verify the request through the organization's official channel.",
    ]


def exception_case(
    channel: str,
    error: Exception | None = None,
) -> dict[str, Any]:
    """
    Create a safe failure result.

    An internal failure is NEVER represented as SAFE.
    """

    result = {
        "risk": "UNKNOWN",
        "summary": (
            "ElderShield could not complete the analysis."
        ),
        "reasons": [
            "The analysis engine encountered an internal error."
        ],
        "actions": emergency_actions(),
        "categories": [],
        "dangerous_actions": [],
        "signal_groups": [],
        "channels": [channel],
    }

    # Show technical information only when explicitly enabled.
    if st.session_state.get(
        "show_debug",
        False,
    ) and error is not None:
        result["debug_error"] = str(error)

    return result


def build_text_case(
    text: str,
    channel: str,
) -> dict[str, Any]:
    """
    Primary deterministic message analysis.

    This function does not require Gemini or network access.
    """

    try:
        result = analyze_text_rules(
            text
        )

        if not isinstance(
            result,
            dict,
        ):
            return exception_case(
                channel
            )

        risk = clean_risk(
            result.get(
                "risk",
                "UNKNOWN",
            )
        )

        reasons = merge_unique(
            result.get("reasons", []),
        )

        actions = emergency_actions()

        dangerous_actions = merge_unique(
            result.get(
                "dangerous_actions",
                [],
            )
        )

        categories = merge_unique(
            result.get(
                "categories",
                [],
            )
        )

        signal_groups = merge_unique(
            result.get(
                "signal_groups",
                [],
            )
        )

        # A deterministic critical action is never downgraded.
        critical_terms = {
            "OTP",
            "UPI PIN",
            "ATM PIN",
            "PASSWORD",
            "CVV",
            "BANK CREDENTIALS",
            "REMOTE ACCESS",
            "SCREEN SHARING",
            "MONEY TRANSFER",
            "PAYMENT",
            "PAYMENT APPROVAL",
        }

        action_text = {
            item.upper()
            for item in dangerous_actions
        }

        if action_text.intersection(
            critical_terms
        ):
            risk = "CRITICAL"

        if risk == "SAFE":
            actions = [
                "No strong scam indicators were detected.",
                "Still verify unexpected financial requests independently.",
            ]

        elif risk == "CAUTION":
            actions = [
                "Pause before responding.",
                "Do not share sensitive information.",
                "Verify the sender independently.",
            ]

        elif risk == "HIGH":
            actions = [
                "Do not click suspicious links.",
                "Do not install unknown applications.",
                "Do not provide financial or credential information.",
                "Verify through an official channel.",
            ]

        return {
            "risk": risk,
            "summary": (
                "ElderShield analyzed the submitted content "
                "using local safety rules."
            ),
            "reasons": reasons,
            "actions": actions,
            "categories": categories,
            "dangerous_actions": dangerous_actions,
            "signal_groups": signal_groups,
            "channels": [channel],
            "deterministic_evidence": result,
        }

    except Exception as exc:
        return exception_case(
            channel,
            exc,
        )


def build_url_case(
    url: str,
) -> dict[str, Any]:
    """Analyze a URL without opening it."""

    try:
        result = analyze_url(
            url
        )

        if not isinstance(
            result,
            dict,
        ):
            return exception_case(
                "url"
            )

        risk = clean_risk(
            result.get(
                "risk",
                "UNKNOWN",
            )
        )

        reasons = merge_unique(
            result.get(
                "reasons",
                [],
            )
        )

        indicators = merge_unique(
            result.get(
                "indicators",
                [],
            )
        )

        if indicators:
            reasons.extend(
                item
                for item in indicators
                if item not in reasons
            )

        if risk == "SAFE":
            actions = [
                "No strong structural warning was detected.",
                "Still verify unexpected links before entering information.",
            ]

        elif risk == "CAUTION":
            actions = [
                "Pause before opening the link.",
                "Check the domain carefully.",
                "Verify the website independently.",
            ]

        else:
            actions = [
                "Do not open the suspicious link.",
                "Do not enter passwords, OTPs or banking information.",
                "Visit the organization's official website manually.",
            ]

        return {
            "risk": risk,
            "summary": (
                "ElderShield analyzed the URL structure "
                "without opening the website."
            ),
            "reasons": reasons,
            "actions": actions,
            "categories": [],
            "dangerous_actions": [],
            "signal_groups": [],
            "channels": ["url"],
            "url_analysis": result,
        }

    except Exception as exc:
        return exception_case(
            "url",
            exc,
        )


def build_call_case(
    text: str,
) -> dict[str, Any]:
    """Analyze caller statements using deterministic rules."""

    try:
        call_result = assess_call_text(
            text
        )

        text_result = analyze_text_rules(
            text
        )

        call_risk = clean_risk(
            call_result.get(
                "risk",
                "UNKNOWN",
            )
        )

        text_risk = clean_risk(
            text_result.get(
                "risk",
                "UNKNOWN",
            )
        )

        risk = highest_risk(
            call_risk,
            text_risk,
        )

        reasons = merge_unique(
            call_result.get(
                "reasons",
                [],
            ),
            text_result.get(
                "reasons",
                [],
            ),
        )

        dangerous_actions = merge_unique(
            call_result.get(
                "dangerous_actions",
                [],
            ),
            text_result.get(
                "dangerous_actions",
                [],
            ),
        )

        categories = merge_unique(
            call_result.get(
                "categories",
                [],
            ),
            text_result.get(
                "categories",
                [],
            ),
        )

        signal_groups = merge_unique(
            text_result.get(
                "signal_groups",
                [],
            )
        )

        # Explicit credential/remote-access requests are critical.
        action_text = {
            item.upper()
            for item in dangerous_actions
        }

        critical_terms = {
            "OTP",
            "UPI PIN",
            "ATM PIN",
            "PASSWORD",
            "CVV",
            "REMOTE ACCESS",
            "SCREEN SHARING",
            "MONEY TRANSFER",
            "PAYMENT",
        }

        if action_text.intersection(
            critical_terms
        ):
            risk = "CRITICAL"

        if risk == "SAFE":
            actions = [
                "No strong scam indicators were detected.",
                "Still verify unexpected caller claims independently.",
            ]

        elif risk == "CAUTION":
            actions = [
                "Pause and verify who is calling.",
                "Do not share sensitive information.",
            ]

        elif risk == "HIGH":
            actions = [
                "Do not follow payment or credential instructions.",
                "End the interaction if pressure continues.",
                "Verify the organization independently.",
            ]

        else:
            actions = emergency_actions()

        return {
            "risk": risk,
            "summary": (
                "ElderShield assessed the caller statement "
                "using local safety rules."
            ),
            "reasons": reasons,
            "actions": actions,
            "categories": categories,
            "dangerous_actions": dangerous_actions,
            "signal_groups": signal_groups,
            "channels": ["call"],
            "call_evidence": call_result,
        }

    except Exception as exc:
        return exception_case(
            "call",
            exc,
        )


# ============================================================
# DISPLAY
# ============================================================

def display_risk(risk: str) -> None:
    """Display risk prominently."""

    level = clean_risk(
        risk
    )

    emoji = RISK_EMOJI[
        level
    ]

    st.subheader(
        f"{emoji} {level}"
    )

    if level == "SAFE":
        st.success(
            "No strong scam indicators were detected. "
            "Continue to verify important requests."
        )

    elif level == "CAUTION":
        st.warning(
            "Some warning signs were detected. "
            "Pause and verify before taking action."
        )

    elif level == "HIGH":
        st.warning(
            "This content looks suspicious. "
            "Do not provide sensitive information or make payments."
        )

    elif level == "CRITICAL":
        st.error(
            "STOP. A critical scam signal was detected. "
            "Do not share OTPs, PINs, passwords or approve payments."
        )

    else:
        st.info(
            "ElderShield could not establish a reliable safety verdict. "
            "Treat the content cautiously and verify independently."
        )


def display_items(
    title: str,
    items: Any,
) -> None:
    """Display a list of findings."""

    if not items:
        return

    st.markdown(
        f"**{title}**"
    )

    for item in items:
        value = str(
            item
        ).strip()

        if value:
            st.markdown(
                f"- {value}"
            )


def display_case(
    case: dict[str, Any],
) -> None:
    """Display a standardized analysis result."""

    if not isinstance(
        case,
        dict,
    ):
        st.error(
            "Invalid ElderShield result."
        )
        return

    display_risk(
        case.get(
            "risk",
            "UNKNOWN",
        )
    )

    summary = case.get(
        "summary"
    )

    if summary:
        st.markdown(
            f"### What ElderShield found\n\n{summary}"
        )

    display_items(
        "Why this was flagged",
        case.get(
            "reasons",
            [],
        ),
    )

    display_items(
        "Dangerous actions detected",
        case.get(
            "dangerous_actions",
            [],
        ),
    )

    display_items(
        "Recommended actions",
        case.get(
            "actions",
            [],
        ),
    )

    display_items(
        "Scam categories",
        case.get(
            "categories",
            [],
        ),
    )

    display_items(
        "Signal groups",
        case.get(
            "signal_groups",
            [],
        ),
    )

    channels = case.get(
        "channels",
        []
    )

    if channels:
        st.caption(
            "Evidence channel(s): "
            + ", ".join(
                str(item)
                for item in channels
            )
        )

    if case.get(
        "debug_error"
    ):
        st.error(
            "Development diagnostic: "
            + str(
                case["debug_error"]
            )
        )


def save_case(
    case: dict[str, Any],
) -> None:
    """Save privacy-conscious history only."""

    item = {
        "risk": clean_risk(
            case.get(
                "risk",
                "UNKNOWN",
            )
        ),
        "summary": str(
            case.get(
                "summary",
                "",
            )
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
        item,
    )

    st.session_state.history = (
        st.session_state.history[:20]
    )

    st.session_state.last_case = case


def display_report(
    case: dict[str, Any],
) -> None:
    """Display privacy-conscious report."""

    try:
        report = report_from_case(
            case
        )

        with st.expander(
            "📋 View safety report"
        ):

            st.markdown(
                report_to_markdown(
                    report
                )
            )

            st.download_button(
                "Download text report",
                report_to_text(
                    report
                ),
                file_name="eldershield_report.txt",
                mime="text/plain",
            )

    except Exception as exc:

        if st.session_state.get(
            "show_debug",
            False,
        ):
            st.caption(
                f"Report unavailable: {exc}"
            )


# ============================================================
# HEADER
# ============================================================

st.title(
    "🛡️ ElderShield"
)

st.markdown(
    """
### Show ElderShield what you are seeing, and it tells you what to do.

**STOP → CHECK → PROTECT**

ElderShield is an open-source safety aid designed to help
people recognize phishing, impersonation and scam patterns.
"""
)

st.caption(
    f"Version {APP_VERSION} • "
    "Open-source social-benefit project"
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header(
        "🛡️ ElderShield"
    )

    st.markdown(
        """
**Golden rule**

> Stop first.  
> Check second.  
> Pay or share nothing until verified.
        """
    )

    st.divider()

    st.subheader(
        "🔐 Privacy"
    )

    st.caption(
        "Never intentionally enter a real OTP, "
        "UPI PIN, ATM PIN, password, CVV or full card number."
    )

    st.divider()

    st.subheader(
        "System status"
    )

    try:
        health = run_health_check()

        if health.get(
            "ok",
            False,
        ):
            st.success(
                "Core modules: OK"
            )
        else:
            st.warning(
                "Some modules need attention."
            )

    except Exception:
        st.warning(
            "Health check unavailable."
        )

    st.checkbox(
        "Show technical diagnostics",
        key="show_debug",
        help=(
            "Useful during development. "
            "Do not enable this for ordinary users."
        ),
    )


# ============================================================
# PRIVACY GATE
# ============================================================

if not st.session_state.privacy_acknowledged:

    st.warning(
        """
### Before using ElderShield

Do not intentionally submit:

- OTP
- UPI PIN
- ATM PIN
- Password
- CVV
- Full card credentials

Screenshots, links, messages and audio should always be treated
as untrusted evidence.
"""
    )

    acknowledged = st.checkbox(
        "I understand and will not intentionally submit passwords, PINs or OTPs."
    )

    if st.button(
        "Continue",
        type="primary",
        disabled=not acknowledged,
    ):
        st.session_state.privacy_acknowledged = True
        st.rerun()

    st.stop()


# ============================================================
# MAIN TABS
# ============================================================

screen_tab, message_tab, call_tab, url_tab = st.tabs(
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

with screen_tab:

    st.header(
        "🖥️ Screen Guardian"
    )

    st.write(
        "Upload a screenshot of a suspicious message, "
        "website, payment request or pop-up."
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

    if image_file:

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
                "🔍 Check screen",
                type="primary",
                key="screen_button",
            ):

                if analyze_screen is None:

                    st.warning(
                        "AI screen analysis is currently unavailable."
                    )

                    case = {
                        "risk": "UNKNOWN",
                        "summary": (
                            "Screen AI analysis is unavailable."
                        ),
                        "reasons": [
                            "The Gemini screen-analysis module could not be loaded."
                        ],
                        "actions": emergency_actions(),
                        "channels": ["screen"],
                    }

                else:

                    with st.spinner(
                        "Analyzing screen..."
                    ):

                        try:

                            ai_result = analyze_screen(
                                image_bytes
                            )

                            if not isinstance(
                                ai_result,
                                dict,
                            ):
                                raise ValueError(
                                    "Invalid AI result."
                                )

                            ai_risk = clean_risk(
                                ai_result.get(
                                    "risk",
                                    "UNKNOWN",
                                )
                            )

                            reasons = merge_unique(
                                ai_result.get(
                                    "reasons",
                                    [],
                                )
                            )

                            dangerous = merge_unique(
                                ai_result.get(
                                    "dangerous_actions",
                                    [],
                                )
                            )

                            if ai_risk == "CRITICAL":
                                actions = emergency_actions()
                            elif ai_risk == "HIGH":
                                actions = [
                                    "Do not click suspicious links.",
                                    "Do not provide credentials.",
                                    "Verify the request independently.",
                                ]
                            else:
                                actions = [
                                    "Verify important requests independently.",
                                ]

                            case = {
                                "risk": ai_risk,
                                "summary": ai_result.get(
                                    "summary",
                                    "Screen evidence analyzed.",
                                ),
                                "reasons": reasons,
                                "actions": actions,
                                "categories": [],
                                "dangerous_actions": dangerous,
                                "signal_groups": [],
                                "channels": ["screen"],
                                "ai_evidence": ai_result,
                            }

                        except Exception as exc:

                            case = exception_case(
                                "screen",
                                exc,
                            )

                save_case(
                    case
                )

                display_case(
                    case
                )

                display_report(
                    case
                )


# ============================================================
# MESSAGE GUARDIAN
# ============================================================

with message_tab:

    st.header(
        "💬 Message Guardian"
    )

    st.write(
        "Paste an SMS, WhatsApp message, email text or "
        "other suspicious message."
    )

    message = st.text_area(
        "Message",
        height=220,
        placeholder=(
            "Paste the suspicious message here..."
        ),
        key="message_input",
    )

    if st.button(
        "🔍 Check message",
        type="primary",
        key="message_button",
    ):

        if not message.strip():

            st.warning(
                "Please enter a message first."
            )

        else:

            with st.spinner(
                "Checking message..."
            ):

                case = build_text_case(
                    message.strip(),
                    "message",
                )

            save_case(
                case
            )

            display_case(
                case
            )

            display_report(
                case
            )


# ============================================================
# CALL GUARDIAN
# ============================================================

with call_tab:

    st.header(
        "📞 Incoming Call Guardian"
    )

    st.warning(
        """
An unknown caller is not automatically a scam.

Risk increases when the caller uses urgency, threats,
impersonation, financial requests, credential requests,
remote-access instructions or secrecy.
"""
    )

    st.subheader(
        "Demo scenarios"
    )

    scenario = st.selectbox(
        "Select a scenario",
        [
            "Unknown caller",
            "Bank/KYC urgency",
            "Digital arrest",
            "Job fee request",
            "Investment guarantee",
            "Normal call",
        ],
        key="call_scenario",
    )

    scenarios = {
        "Unknown caller": (
            "An unknown caller is calling. "
            "No claim or request has been provided."
        ),
        "Bank/KYC urgency": (
            "I am calling from your bank. "
            "Your account will be blocked today. "
            "Give me the OTP immediately to complete KYC."
        ),
        "Digital arrest": (
            "You are involved in a criminal case. "
            "Stay on this video call and follow our instructions "
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
        "📞 Assess call",
        type="primary",
        key="call_button",
    ):

        case = build_call_case(
            scenarios[scenario]
        )

        save_case(
            case
        )

        display_case(
            case
        )

        display_report(
            case
        )

    st.divider()

    st.subheader(
        "Analyze caller statement"
    )

    call_text = st.text_area(
        "What did the caller say?",
        height=180,
        placeholder=(
            "Example: I am calling from your bank..."
        ),
        key="call_statement",
    )

    if st.button(
        "🔍 Check caller statement",
        key="caller_text_button",
    ):

        if not call_text.strip():

            st.warning(
                "Please enter the caller's statement."
            )

        else:

            case = build_call_case(
                call_text.strip()
            )

            save_case(
                case
            )

            display_case(
                case
            )

            display_report(
                case
            )


# ============================================================
# URL GUARDIAN
# ============================================================

with url_tab:

    st.header(
        "🔗 URL Guardian"
    )

    st.write(
        "Paste a link here **before opening it**."
    )

    st.warning(
        "ElderShield analyzes the URL structure. "
        "It does not automatically open the website."
    )

    url = st.text_input(
        "URL",
        placeholder="https://example.org",
        key="url_input",
    )

    if st.button(
        "🔍 Check URL",
        type="primary",
        key="url_button",
    ):

        if not url.strip():

            st.warning(
                "Please enter a URL."
            )

        else:

            case = build_url_case(
                url.strip()
            )

            save_case(
                case
            )

            display_case(
                case
            )

            display_report(
                case
            )


# ============================================================
# SESSION HISTORY
# ============================================================

st.divider()

st.header(
    "🧾 Recent checks"
)

if not st.session_state.history:

    st.caption(
        "No checks have been recorded in this browser session."
    )

else:

    for item in st.session_state.history:

        risk = clean_risk(
            item.get(
                "risk",
                "UNKNOWN",
            )
        )

        emoji = RISK_EMOJI[
            risk
        ]

        summary = item.get(
            "summary",
            "Safety check",
        )

        with st.expander(
            f"{emoji} {risk} — {summary[:100]}"
        ):

            st.write(
                summary
            )

            categories = item.get(
                "categories",
                [],
            )

            channels = item.get(
                "channels",
                [],
            )

            if categories:
                st.caption(
                    "Categories: "
                    + ", ".join(
                        str(x)
                        for x in categories
                    )
                )

            if channels:
                st.caption(
                    "Channel: "
                    + ", ".join(
                        str(x)
                        for x in channels
                    )
                )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.markdown(
    """
### 🛡️ Remember

**Never share an OTP, UPI PIN, ATM PIN, password or CVV with a caller,
message sender or website.**

If someone pressures you to act immediately, **stop and verify independently.**

ElderShield is a safety aid, not a guarantee. The current web version
cannot silently monitor cellular calls, WhatsApp, other apps or bank
transactions. Such capabilities would require a future native platform
implementation.
"""
)

st.caption(
    "ElderShield • Open-source • Social benefit"
)
