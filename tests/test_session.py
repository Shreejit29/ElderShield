"""
Tests for ElderShield session and privacy-conscious history.
"""

from modules.session import (
    initialize_session_state,
    add_history_item,
    get_history,
    clear_history,
    get_session_snapshot,
)


class FakeSessionState(dict):
    """
    Small Streamlit-session-state-compatible object for testing.
    """

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name, value):
        self[name] = value


def test_initialize_session_state():
    state = FakeSessionState()

    initialize_session_state(state)

    assert "history" in state
    assert "current_case" in state
    assert "privacy_acknowledged" in state
    assert "language" in state


def test_history_starts_empty():
    state = FakeSessionState()

    initialize_session_state(state)

    assert get_history(state) == []


def test_add_history_item():
    state = FakeSessionState()

    initialize_session_state(state)

    add_history_item(
        state,
        {
            "risk": "HIGH",
            "summary": "Suspicious request.",
            "categories": ["bank_kyc"],
            "channels": ["MESSAGE"],
        },
    )

    history = get_history(state)

    assert len(history) == 1
    assert history[0]["risk"] == "HIGH"


def test_raw_message_is_not_stored():
    state = FakeSessionState()

    initialize_session_state(state)

    add_history_item(
        state,
        {
            "risk": "CRITICAL",
            "summary": "OTP request detected.",
            "message": "My OTP is 123456",
            "dangerous_actions": ["OTP"],
        },
    )

    history = get_history(state)

    serialized = str(history)

    assert "123456" not in serialized
    assert "My OTP is 123456" not in serialized


def test_history_has_privacy_conscious_fields():
    state = FakeSessionState()

    initialize_session_state(state)

    add_history_item(
        state,
        {
            "risk": "HIGH",
            "summary": "Suspicious message.",
            "categories": ["job"],
            "channels": ["MESSAGE"],
        },
    )

    item = get_history(state)[0]

    assert "risk" in item
    assert "summary" in item
    assert "categories" in item
    assert "channels" in item


def test_history_limit_is_enforced():
    state = FakeSessionState()

    initialize_session_state(state)

    for index in range(30):
        add_history_item(
            state,
            {
                "risk": "CAUTION",
                "summary": f"Case {index}",
                "categories": [],
                "channels": ["MESSAGE"],
            },
        )

    history = get_history(state)

    assert len(history) <= 20


def test_clear_history():
    state = FakeSessionState()

    initialize_session_state(state)

    add_history_item(
        state,
        {
            "risk": "HIGH",
            "summary": "Suspicious request.",
            "categories": [],
            "channels": ["MESSAGE"],
        },
    )

    clear_history(state)

    assert get_history(state) == []


def test_session_snapshot_is_safe():
    state = FakeSessionState()

    initialize_session_state(state)

    state["current_case"] = {
        "risk": "CRITICAL",
        "message": "OTP 123456",
        "password": "secret",
    }

    snapshot = get_session_snapshot(state)

    serialized = str(snapshot)

    assert "123456" not in serialized
    assert "secret" not in serialized


def test_language_has_default_value():
    state = FakeSessionState()

    initialize_session_state(state)

    assert isinstance(
        state["language"],
        str,
    )

    assert len(
        state["language"]
    ) > 0
