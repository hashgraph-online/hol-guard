"""Tests for scanner engine and models."""

import tempfile
from pathlib import Path

from codex_plugin_scanner.models import GRADE_LABELS, CategoryResult, CheckResult, ScanResult, get_grade
from codex_plugin_scanner.scanner import scan_plugin

FIXTURES = Path(__file__).parent / "fixtures"


class TestGetGrade:
    def test_a_boundary(self):
        assert get_grade(90) == "A"
        assert get_grade(100) == "A"

    def test_b_boundary(self):
        assert get_grade(80) == "B"
        assert get_grade(89) == "B"

    def test_c_boundary(self):
        assert get_grade(70) == "C"
        assert get_grade(79) == "C"

    def test_d_boundary(self):
        assert get_grade(60) == "D"
        assert get_grade(69) == "D"

    def test_f(self):
        assert get_grade(0) == "F"
        assert get_grade(59) == "F"


class TestGradeLabels:
    def test_all_labels_present(self):
        assert GRADE_LABELS == {
            "A": "Excellent",
            "B": "Good",
            "C": "Acceptable",
            "D": "Needs Improvement",
            "F": "Failing",
        }


class TestModels:
    def test_check_result_immutable(self):
        cr = CheckResult(name="test", passed=True, points=5, max_points=5, message="ok")
        assert cr.passed is True
        assert hash(cr) is not None  # frozen dataclass is hashable

    def test_category_result(self):
        cr = CheckResult(name="t", passed=True, points=5, max_points=5, message="ok")
        cat = CategoryResult(name="Cat", checks=(cr,))
        assert cat.name == "Cat"
        assert len(cat.checks) == 1

    def test_scan_result(self):
        cr = CheckResult(name="t", passed=True, points=5, max_points=5, message="ok")
        cat = CategoryResult(name="Cat", checks=(cr,))
        sr = ScanResult(score=5, grade="F", categories=(cat,), timestamp="now", plugin_dir="/tmp")
        assert sr.score == 5
        assert sr.grade == "F"


class TestScanPlugin:
    def test_good_plugin_scores_100(self):
        result = scan_plugin(FIXTURES / "good-plugin")
        assert result.score == 100
        assert result.grade == "A"
        assert result.timestamp  # non-empty
        assert "good-plugin" in result.plugin_dir

    def test_bad_plugin_scores_below_60(self):
        result = scan_plugin(FIXTURES / "bad-plugin")
        assert result.score < 60
        assert result.grade == "F"

    def test_minimal_plugin_scores_73(self):
        result = scan_plugin(FIXTURES / "minimal-plugin")
        assert result.score == 73
        assert result.grade == "C"

    def test_empty_dir_scores_38(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = scan_plugin(tmpdir)
            assert result.score == 38

    def test_mit_license_detected(self):
        result = scan_plugin(FIXTURES / "mit-license")
        sec_cat = next(c for c in result.categories if c.name == "Security")
        license_check = next(c for c in sec_cat.checks if c.name == "LICENSE found")
        assert license_check.passed

    def test_accepts_pathlib_and_string(self):
        r1 = scan_plugin(str(FIXTURES / "good-plugin"))
        r2 = scan_plugin(FIXTURES / "good-plugin")
        assert r1.score == r2.score

    def test_returns_6_categories(self):
        result = scan_plugin(FIXTURES / "good-plugin")
        assert len(result.categories) == 6
        names = [c.name for c in result.categories]
        assert "Manifest Validation" in names
        assert "Security" in names
        assert "Best Practices" in names
        assert "Marketplace" in names
        assert "Skill Security" in names
        assert "Code Quality" in names

    def test_with_marketplace_plugin(self):
        result = scan_plugin(FIXTURES / "with-marketplace")
        mp_cat = next(c for c in result.categories if c.name == "Marketplace")
        assert sum(c.points for c in mp_cat.checks) == 15
