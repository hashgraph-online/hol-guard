"""Tests for scanner and grading."""

from pathlib import Path

from codex_plugin_scanner.scanner import scan_plugin
from codex_plugin_scanner.models import get_grade, GRADE_LABELS

FIXTURES = Path(__file__).parent / "fixtures"


def test_good_plugin_scores_100():
    result = scan_plugin(FIXTURES / "good-plugin")
    assert result.score == 100
    assert result.grade == "A"


def test_bad_plugin_scores_below_60():
    result = scan_plugin(FIXTURES / "bad-plugin")
    assert result.score < 60
    assert result.grade == "F"


def test_minimal_plugin_scores_80():
    result = scan_plugin(FIXTURES / "minimal-plugin")
    assert result.score == 80
    assert result.grade == "B"


def test_grades():
    assert get_grade(95) == "A"
    assert get_grade(85) == "B"
    assert get_grade(75) == "C"
    assert get_grade(65) == "D"
    assert get_grade(40) == "F"


def test_grade_labels():
    assert GRADE_LABELS["A"] == "Excellent"
    assert GRADE_LABELS["B"] == "Good"
    assert GRADE_LABELS["C"] == "Acceptable"
    assert GRADE_LABELS["D"] == "Needs Improvement"
    assert GRADE_LABELS["F"] == "Failing"
