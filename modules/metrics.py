"""
ElderShield Evaluation Metrics

Provides metrics for testing and evaluating ElderShield.

This module works with structured predictions and labels.

It does NOT:
- collect personal information
- store raw messages
- store screenshots
- store audio
- contact external services

Metrics are intended for development and evaluation.
"""

from __future__ import annotations

from typing import Any, Iterable


# ============================================================
# CONSTANTS
# ============================================================

SCAM_LABELS = {
    "SCAM",
    "FRAUD",
    "MALICIOUS",
    "DANGEROUS",
    "HIGH",
    "CRITICAL",
}

SAFE_LABELS = {
    "SAFE",
    "BENIGN",
    "NORMAL",
}


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_label(
    value: Any,
) -> str:
    """
    Normalize an evaluation label.
    """

    return str(
        value or ""
    ).strip().upper()


def is_scam_label(
    value: Any,
) -> bool:
    """
    Determine whether a label represents scam/dangerous content.
    """

    return normalize_label(
        value
    ) in SCAM_LABELS


def is_safe_label(
    value: Any,
) -> bool:
    """
    Determine whether a label represents safe/benign content.
    """

    return normalize_label(
        value
    ) in SAFE_LABELS


# ============================================================
# CONFUSION MATRIX
# ============================================================

def confusion_matrix(
    actual: Iterable[Any],
    predicted: Iterable[Any],
) -> dict[str, int]:
    """
    Calculate binary scam/safe confusion-matrix counts.

    Returns:
        TP, TN, FP, FN

    Any label not explicitly recognized as safe is treated
    according to is_scam_label(). Unknown labels therefore
    should ideally be avoided in benchmark datasets.
    """

    actual_list = list(
        actual
    )

    predicted_list = list(
        predicted
    )

    if len(actual_list) != len(
        predicted_list
    ):

        raise ValueError(
            "Actual and predicted lists must have the same length."
        )

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    for actual_value, predicted_value in zip(
        actual_list,
        predicted_list,
    ):

        actual_scam = is_scam_label(
            actual_value
        )

        predicted_scam = is_scam_label(
            predicted_value
        )

        if actual_scam and predicted_scam:

            tp += 1

        elif not actual_scam and not predicted_scam:

            tn += 1

        elif not actual_scam and predicted_scam:

            fp += 1

        elif actual_scam and not predicted_scam:

            fn += 1

    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "total": (
            tp
            + tn
            + fp
            + fn
        ),
    }


# ============================================================
# METRICS
# ============================================================

def _safe_divide(
    numerator: float,
    denominator: float,
) -> float:
    """
    Safe division.
    """

    if denominator == 0:

        return 0.0

    return numerator / denominator


def calculate_metrics(
    matrix: dict[str, int],
) -> dict[str, float]:
    """
    Calculate standard binary classification metrics.
    """

    tp = float(
        matrix.get(
            "TP",
            0,
        )
    )

    tn = float(
        matrix.get(
            "TN",
            0,
        )
    )

    fp = float(
        matrix.get(
            "FP",
            0,
        )
    )

    fn = float(
        matrix.get(
            "FN",
            0,
        )
    )

    total = (
        tp
        + tn
        + fp
        + fn
    )

    accuracy = _safe_divide(
        tp + tn,
        total,
    )

    precision = _safe_divide(
        tp,
        tp + fp,
    )

    recall = _safe_divide(
        tp,
        tp + fn,
    )

    specificity = _safe_divide(
        tn,
        tn + fp,
    )

    f1 = _safe_divide(
        2 * precision * recall,
        precision + recall,
    )

    false_positive_rate = _safe_divide(
        fp,
        fp + tn,
    )

    false_negative_rate = _safe_divide(
        fn,
        fn + tp,
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
    }


def evaluate_predictions(
    actual: Iterable[Any],
    predicted: Iterable[Any],
) -> dict[str, Any]:
    """
    Calculate the confusion matrix and evaluation metrics.
    """

    matrix = confusion_matrix(
        actual,
        predicted,
    )

    metrics = calculate_metrics(
        matrix
    )

    return {
        "confusion_matrix": matrix,
        "metrics": metrics,
    }


# ============================================================
# RISK DISTRIBUTION
# ============================================================

def risk_distribution(
    results: Iterable[Any],
) -> dict[str, int]:
    """
    Count ElderShield risk levels.

    Expected values:
        SAFE
        CAUTION
        HIGH
        CRITICAL
        UNKNOWN
    """

    distribution = {
        "SAFE": 0,
        "CAUTION": 0,
        "HIGH": 0,
        "CRITICAL": 0,
        "UNKNOWN": 0,
    }

    for item in results:

        if isinstance(
            item,
            dict,
        ):

            risk = normalize_label(
                item.get(
                    "risk",
                    "UNKNOWN",
                )
            )

        else:

            risk = normalize_label(
                item
            )

        if risk not in distribution:

            risk = "UNKNOWN"

        distribution[
            risk
        ] += 1

    return distribution


# ============================================================
# SAFETY STATISTICS
# ============================================================

def count_critical_results(
    results: Iterable[Any],
) -> int:
    """
    Count results classified as CRITICAL.
    """

    count = 0

    for item in results:

        if isinstance(
            item,
            dict,
        ):

            risk = normalize_label(
                item.get(
                    "risk",
                    "",
                )
            )

        else:

            risk = normalize_label(
                item
            )

        if risk == "CRITICAL":

            count += 1

    return count


def count_actionable_results(
    results: Iterable[Any],
) -> int:
    """
    Count results that require caution or action.
    """

    actionable = {
        "CAUTION",
        "HIGH",
        "CRITICAL",
    }

    count = 0

    for item in results:

        if isinstance(
            item,
            dict,
        ):

            risk = normalize_label(
                item.get(
                    "risk",
                    "",
                )
            )

        else:

            risk = normalize_label(
                item
            )

        if risk in actionable:

            count += 1

    return count


# ============================================================
# BENCHMARK SUMMARY
# ============================================================

def benchmark_summary(
    actual: Iterable[Any],
    predicted: Iterable[Any],
) -> dict[str, Any]:
    """
    Produce a compact benchmark summary suitable for development
    reports or README documentation.
    """

    evaluation = evaluate_predictions(
        actual,
        predicted,
    )

    matrix = evaluation[
        "confusion_matrix"
    ]

    metrics = evaluation[
        "metrics"
    ]

    return {
        "total_cases": matrix[
            "total"
        ],

        "true_positives": matrix[
            "TP"
        ],

        "true_negatives": matrix[
            "TN"
        ],

        "false_positives": matrix[
            "FP"
        ],

        "false_negatives": matrix[
            "FN"
        ],

        "accuracy": round(
            metrics[
                "accuracy"
            ],
            4,
        ),

        "precision": round(
            metrics[
                "precision"
            ],
            4,
        ),

        "recall": round(
            metrics[
                "recall"
            ],
            4,
        ),

        "specificity": round(
            metrics[
                "specificity"
            ],
            4,
        ),

        "f1": round(
            metrics[
                "f1"
            ],
            4,
        ),

        "false_positive_rate": round(
            metrics[
                "false_positive_rate"
            ],
            4,
        ),

        "false_negative_rate": round(
            metrics[
                "false_negative_rate"
            ],
            4,
        ),
    }


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "SCAM_LABELS",
    "SAFE_LABELS",
    "normalize_label",
    "is_scam_label",
    "is_safe_label",
    "confusion_matrix",
    "calculate_metrics",
    "evaluate_predictions",
    "risk_distribution",
    "count_critical_results",
    "count_actionable_results",
    "benchmark_summary",
]
