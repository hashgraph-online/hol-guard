"""Validate every reported gate condition without weakening configured thresholds."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation

REQUIRED_METRICS = {
    "new_reliability_rating",
    "new_security_rating",
    "new_maintainability_rating",
    "new_duplicated_lines_density",
    "new_security_hotspots_reviewed",
}


def number(value: object) -> Decimal:
    """Reject missing, nonnumeric and nonfinite API measurements."""
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Missing or invalid Sonar measurement")
    try:
        result = Decimal(value)
    except InvalidOperation as error:
        raise ValueError("Invalid Sonar measurement") from error
    if not result.is_finite():
        raise ValueError("Nonfinite Sonar measurement")
    return result


def conditions(gate: dict) -> dict[str, dict]:
    """Require complete, unambiguous gate results, including security findings."""
    if gate.get("status") not in {"OK", "ERROR"} or not isinstance(gate.get("conditions"), list):
        raise ValueError("Sonar gate is missing or incomplete")
    result = {}
    for condition in gate["conditions"]:
        if not isinstance(condition, dict):
            raise ValueError("Malformed Sonar condition")
        metric = condition.get("metricKey")
        if not isinstance(metric, str) or not metric or len(metric) > 128 or metric in result:
            raise ValueError("Duplicate or invalid Sonar metric")
        if condition.get("status") not in {"OK", "ERROR"}:
            raise ValueError("Sonar condition has not completed")
        if condition.get("comparator") not in {"LT", "GT"}:
            raise ValueError("Unknown Sonar comparator")
        actual, threshold = number(condition.get("actualValue")), number(condition.get("errorThreshold"))
        maximums = {
            "new_reliability_rating": 1,
            "new_security_rating": 1,
            "new_maintainability_rating": 1,
            "new_duplicated_lines_density": 3,
        }
        if metric in maximums and (condition["comparator"] != "GT" or threshold > maximums[metric]):
            raise ValueError("Security or quality threshold was weakened")
        minimums = {"new_security_hotspots_reviewed": 100, "new_coverage": 80}
        if metric in minimums and (condition["comparator"] != "LT" or threshold < minimums[metric]):
            raise ValueError("Coverage or hotspot review threshold was weakened")
        failed = actual < threshold if condition["comparator"] == "LT" else actual > threshold
        if failed != (condition["status"] == "ERROR"):
            raise ValueError("Inconsistent Sonar condition")
        result[metric] = condition
    if not result.keys() >= REQUIRED_METRICS:
        raise ValueError("Required security or quality conditions are missing")
    if (gate["status"] == "ERROR") != any(c["status"] == "ERROR" for c in result.values()):
        raise ValueError("Inconsistent Sonar gate status")
    return result
