"""Tests for code quality checks."""

import tempfile
from pathlib import Path

from codex_plugin_scanner.checks.code_quality import (
    _find_code_files,
    check_no_eval,
    check_no_shell_injection,
    run_code_quality_checks,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestCheckNoEval:
    def test_passes_clean_dir(self):
        r = check_no_eval(FIXTURES / "good-plugin")
        assert r.passed and r.points == 5

    def test_fails_with_eval(self):
        r = check_no_eval(FIXTURES / "code-quality-bad")
        assert not r.passed and r.points == 0
        assert "eval()" in r.message or "Function()" in r.message

    def test_handles_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            r = check_no_eval(Path(tmpdir))
            assert r.passed and r.points == 5


class TestCheckNoShellInjection:
    def test_passes_clean_dir(self):
        r = check_no_shell_injection(FIXTURES / "good-plugin")
        assert r.passed and r.points == 5

    def test_fails_with_shell_injection(self):
        r = check_no_shell_injection(FIXTURES / "code-quality-bad")
        assert not r.passed and r.points == 0

    def test_handles_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            r = check_no_shell_injection(Path(tmpdir))
            assert r.passed and r.points == 5


class TestFindCodeFiles:
    def test_finds_js_files(self):
        files = _find_code_files(FIXTURES / "code-quality-bad")
        names = [f.name for f in files]
        assert "evil.js" in names

    def test_skips_non_code_files(self):
        files = _find_code_files(FIXTURES / "code-quality-bad")
        for f in files:
            assert f.suffix in {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}

    def test_skips_excluded_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            node_dir = Path(tmpdir) / "node_modules" / "pkg"
            node_dir.mkdir(parents=True)
            (node_dir / "index.js").write_text("eval()")
            files = _find_code_files(Path(tmpdir))
            assert len(files) == 0


class TestRunCodeQualityChecks:
    def test_good_plugin_gets_10(self):
        results = run_code_quality_checks(FIXTURES / "good-plugin")
        assert sum(c.points for c in results) == 10

    def test_bad_code_gets_0(self):
        results = run_code_quality_checks(FIXTURES / "code-quality-bad")
        assert sum(c.points for c in results) == 0

    def test_returns_tuple_of_correct_length(self):
        results = run_code_quality_checks(FIXTURES / "good-plugin")
        assert isinstance(results, tuple)
        assert len(results) == 2
