"""
Tests for ElderShield feedback collection.
"""

from modules.feedback import (
    add_feedback,
    get_feedback,
    clear_feedback,
    feedback_summary,
)


class FakeSessionState(dict):
    """Minimal session-state object for testing."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name, value):
        self[name] = value


def setup_state():
    state = FakeSessionState()
    state["feedback"] = []
    return state


def test_add_helpful_feedback():
    state = setup_state()

    add_feedback(
        state,
        helpful="Helpful",
        incident_id="ES-001",
        risk="HIGH",
        channel="MESSAGE",
    )

    feedback = get_feedback(state)

    assert len(feedback) == 1
    assert feedback[0]["helpful"] == "Helpful"


def test_add_not_helpful_feedback():
    state = setup_state()

    add_feedback(
        state,
        helpful="Not Helpful",
        incident_id="ES-002",
        risk="CAUTION",
        channel="URL",
    )

    feedback = get_feedback(state)

    assert feedback[0]["helpful"] == "Not Helpful"


def test_add_unsure_feedback():
    state = setup_state()

    add_feedback(
        state,
        helpful="Unsure",
        incident_id="ES-003",
        risk="UNKNOWN",
        channel="SCREEN",
    )

    feedback = get_feedback(state)

    assert feedback[0]["helpful"] == "Unsure"


def test_feedback_stores_context_not_raw_evidence():
    state = setup_state()

    add_feedback(
        state,
        helpful="Helpful",
        incident_id="ES-004",
        risk="CRITICAL",
        channel="MESSAGE",
    )

    item = get_feedback(state)[0]

    assert item["risk"] == "CRITICAL"
    assert item["channel"] == "MESSAGE"

    assert "message" not in item
    assert "raw_message" not in item
    assert "image" not in item
    assert "audio" not in item


def test_feedback_does_not_store_credentials():
    state = setup_state()

    add_feedback(
        state,
        helpful="Helpful",
        incident_id="ES-005",
        risk="CRITICAL",
        channel="CALL",
    )

    item = get_feedback(state)[0]
    serialized = str(item)

    assert "123456" not in serialized
    assert "password" not in serialized.lower()
    assert "upi pin" not in serialized.lower()


def test_feedback_limit_is_enforced():
    state = setup_state()

    for index in range(75):
        add_feedback(
            state,
            helpful="Helpful",
            incident_id=f"ES-{index}",
            risk="CAUTION",
            channel="MESSAGE",
        )

    feedback = get_feedback(state)

    assert len(feedback) <= 50


def test_clear_feedback():
    state = setup_state()

    add_feedback(
        state,
        helpful="Helpful",
        incident_id="ES-006",
        risk="HIGH",
        channel="URL",
    )

    clear_feedback(state)

    assert get_feedback(state) == []


def test_feedback_summary_counts_helpful():
    state = setup_state()

    add_feedback(
        state,
        helpful="Helpful",
        incident_id="ES-007",
        risk="HIGH",
        channel="MESSAGE",
    )

    add_feedback(
        state,
        helpful="Helpful",
        incident_id="ES-008",
        risk="HIGH",
        channel="CALL",
    )

    summary = feedback_summary(state)

    assert summary["Helpful"] == 2


def test_feedback_summary_counts_not_helpful():
    state = setup_state()

    add_feedback(
        state,
        helpful="Not Helpful",
        incident_id="ES-009",
        risk="CAUTION",
        channel="URL",
    )

    summary = feedback_summary(state)

    assert summary["Not Helpful"] == 1


def test_feedback_summary_counts_unsure():
    state = setup_state()

    add_feedback(
        state,
        helpful="Unsure",
        incident_id="ES-010",
        risk="UNKNOWN",
        channel="SCREEN",
    )

    summary = feedback_summary(state)

    assert summary["Unsure"] == 1


def test_invalid_feedback_is_not_stored():
    state = setup_state()

    add_feedback(
        state,
        helpful="Something Invalid",
        incident_id="ES-011",
        risk="HIGH",
        channel="MESSAGE",
    )

    feedback = get_feedback(state)

    assert len(feedback) == 0


def test_feedback_summary_has_all_categories():
    state = setup_state()

    summary = feedback_summary(state)

    assert "Helpful" in summary
    assert "Not Helpful" in summary
    assert "Unsure" in summary
