"""
Tests for ElderShield evaluation metrics.
"""

from modules.metrics import (
    normalize_label,
    is_scam_label,
    is_safe_label,
    confusion_matrix,
    calculate_metrics,
    evaluate_predictions,
    risk_distribution,
    count_critical_results,
    count_actionable_results,
    benchmark_summary,
)


# ============================================================
# LABEL NORMALIZATION
# ============================================================

def test_normalize_scam_label():
    assert normalize_label("SCAM") == "SCAM"
    assert normalize_label("scam") == "SCAM"
    assert normalize_label("FRAUD") == "SCAM"


def test_normalize_safe_label():
    assert normalize_label("SAFE") == "SAFE"
    assert normalize_label("safe") == "SAFE"
    assert normalize_label("LEGITIMATE") == "SAFE"


def test_scam_label_detection():
    assert is_scam_label("SCAM") is True
    assert is_scam_label("FRAUD") is True
    assert is_scam_label("SAFE") is False


def test_safe_label_detection():
    assert is_safe_label("SAFE") is True
    assert is_safe_label("LEGITIMATE") is True
    assert is_safe_label("SCAM") is False


# ============================================================
# CONFUSION MATRIX
# ============================================================

def test_perfect_confusion_matrix():
    actual = [
        "SCAM",
        "SCAM",
        "SAFE",
        "SAFE",
    ]

    predicted = [
        "SCAM",
        "SCAM",
        "SAFE",
        "SAFE",
    ]

    matrix = confusion_matrix(
        actual,
        predicted,
    )

    assert matrix["TP"] == 2
    assert matrix["TN"] == 2
    assert matrix["FP"] == 0
    assert matrix["FN"] == 0
    assert matrix["total"] == 4


def test_mixed_confusion_matrix():
    actual = [
        "SCAM",
        "SCAM",
        "SAFE",
        "SAFE",
    ]

    predicted = [
        "SCAM",
        "SAFE",
        "SCAM",
        "SAFE",
    ]

    matrix = confusion_matrix(
        actual,
        predicted,
    )

    assert matrix["TP"] == 1
    assert matrix["TN"] == 1
    assert matrix["FP"] == 1
    assert matrix["FN"] == 1


def test_mismatched_lengths_raise_error():
    actual = [
        "SCAM",
        "SAFE",
    ]

    predicted = [
        "SCAM",
    ]

    try:
        confusion_matrix(
            actual,
            predicted,
        )
    except ValueError:
        assert True
    else:
        assert False


# ============================================================
# METRICS
# ============================================================

def test_perfect_metrics():
    matrix = {
        "TP": 50,
        "TN": 50,
        "FP": 0,
        "FN": 0,
        "total": 100,
    }

    metrics = calculate_metrics(
        matrix
    )

    assert metrics["accuracy"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["specificity"] == 1.0
    assert metrics["f1"] == 1.0
    assert metrics["FPR"] == 0.0
    assert metrics["FNR"] == 0.0


def test_metrics_with_false_negatives():
    matrix = {
        "TP": 90,
        "TN": 100,
        "FP": 0,
        "FN": 10,
        "total": 200,
    }

    metrics = calculate_metrics(
        matrix
    )

    assert metrics["recall"] < 1.0
    assert metrics["FNR"] > 0.0
    assert metrics["specificity"] == 1.0


def test_metrics_with_false_positives():
    matrix = {
        "TP": 90,
        "TN": 90,
        "FP": 10,
        "FN": 10,
        "total": 200,
    }

    metrics = calculate_metrics(
        matrix
    )

    assert metrics["precision"] < 1.0
    assert metrics["FPR"] > 0.0


def test_zero_denominator_is_safe():
    matrix = {
        "TP": 0,
        "TN": 0,
        "FP": 0,
        "FN": 0,
        "total": 0,
    }

    metrics = calculate_metrics(
        matrix
    )

    assert metrics["accuracy"] == 0.0
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0


# ============================================================
# EVALUATION
# ============================================================

def test_evaluate_predictions():
    actual = [
        "SCAM",
        "SCAM",
        "SAFE",
        "SAFE",
    ]

    predicted = [
        "SCAM",
        "SCAM",
        "SAFE",
        "SAFE",
    ]

    result = evaluate_predictions(
        actual,
        predicted,
    )

    assert result["matrix"]["TP"] == 2
    assert result["matrix"]["TN"] == 2
    assert result["metrics"]["accuracy"] == 1.0


# ============================================================
# RISK DISTRIBUTION
# ============================================================

def test_risk_distribution():
    results = [
        {"risk": "SAFE"},
        {"risk": "SAFE"},
        {"risk": "CAUTION"},
        {"risk": "HIGH"},
        {"risk": "CRITICAL"},
    ]

    distribution = risk_distribution(
        results
    )

    assert distribution["SAFE"] == 2
    assert distribution["CAUTION"] == 1
    assert distribution["HIGH"] == 1
    assert distribution["CRITICAL"] == 1


# ============================================================
# CRITICAL / ACTIONABLE COUNTS
# ============================================================

def test_count_critical_results():
    results = [
        {"risk": "CRITICAL"},
        {"risk": "HIGH"},
        {"risk": "CRITICAL"},
        {"risk": "SAFE"},
    ]

    assert count_critical_results(
        results
    ) == 2


def test_count_actionable_results():
    results = [
        {"risk": "SAFE"},
        {"risk": "CAUTION"},
        {"risk": "HIGH"},
        {"risk": "CRITICAL"},
        {"risk": "UNKNOWN"},
    ]

    assert count_actionable_results(
        results
    ) == 3


# ============================================================
# BENCHMARK SUMMARY
# ============================================================

def test_benchmark_summary():
    actual = [
        "SCAM",
        "SCAM",
        "SAFE",
        "SAFE",
    ]

    predicted = [
        "SCAM",
        "SCAM",
        "SAFE",
        "SAFE",
    ]

    results = [
        {"risk": "CRITICAL"},
        {"risk": "HIGH"},
        {"risk": "SAFE"},
        {"risk": "CAUTION"},
    ]

    summary = benchmark_summary(
        actual,
        predicted,
        results,
    )

    assert "matrix" in summary
    assert "metrics" in summary
    assert "risk_distribution" in summary
    assert "critical_results" in summary
    assert "actionable_results" in summary


def test_benchmark_summary_does_not_claim_real_world_accuracy():
    actual = [
        "SCAM",
        "SAFE",
    ]

    predicted = [
        "SCAM",
        "SAFE",
    ]

    summary = benchmark_summary(
        actual,
        predicted,
        [],
    )

    # The metrics module produces measurements only.
    # It must not fabricate a real-world accuracy claim.
    serialized = str(summary).lower()

    assert "real-world accuracy" not in serialized
