"""Codex Plugin Scanner - types and data classes."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Result of an individual check."""

    name: str
    passed: bool
    points: int
    max_points: int
    message: str


@dataclass(frozen=True, slots=True)
class CategoryResult:
    """A category containing multiple checks."""

    name: str
    checks: tuple[CheckResult, ...]


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Full result of scanning a plugin directory."""

    score: int
    grade: str
    categories: tuple[CategoryResult, ...]
    timestamp: str
    plugin_dir: str


def get_grade(score: int) -> str:
    """Convert a numeric score to a letter grade."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


GRADE_LABELS: dict[str, str] = {
    "A": "Excellent",
    "B": "Good",
    "C": "Acceptable",
    "D": "Needs Improvement",
    "F": "Failing",
}
