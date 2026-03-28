"""Codex Plugin Scanner - types and data classes."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    points: int
    max_points: int
    message: str


@dataclass(frozen=True)
class CategoryResult:
    name: str
    checks: tuple[CheckResult, ...]


@dataclass(frozen=True)
class ScanResult:
    score: int
    grade: str
    categories: tuple[CategoryResult, ...]
    timestamp: str
    plugin_dir: str


def get_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


GRADE_LABELS = {
    "A": "Excellent",
    "B": "Good",
    "C": "Acceptable",
    "D": "Needs Improvement",
    "F": "Failing",
}
