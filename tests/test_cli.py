"""Tests for CLI output formatting and argument parsing."""

import json
import tempfile
from pathlib import Path

from codex_plugin_scanner.cli import format_json, format_text, main
from codex_plugin_scanner.scanner import scan_plugin

FIXTURES = Path(__file__).parent / "fixtures"


class TestFormatJson:
    def test_valid_json_output(self):
        result = scan_plugin(FIXTURES / "good-plugin")
        output = format_json(result)
        parsed = json.loads(output)
        assert parsed["score"] == 100
        assert parsed["grade"] == "A"
        assert len(parsed["categories"]) == 6
        assert "timestamp" in parsed
        assert "pluginDir" in parsed
        assert "summary" in parsed
        assert "findings" in parsed

    def test_categories_have_correct_structure(self):
        result = scan_plugin(FIXTURES / "good-plugin")
        output = format_json(result)
        parsed = json.loads(output)
        cat = parsed["categories"][0]
        assert "name" in cat
        assert "score" in cat
        assert "max" in cat
        assert "checks" in cat
        check = cat["checks"][0]
        assert "name" in check
        assert "passed" in check
        assert "points" in check
        assert "maxPoints" in check
        assert "message" in check
        assert "findings" in check

    def test_bad_plugin_json(self):
        result = scan_plugin(FIXTURES / "bad-plugin")
        output = format_json(result)
        parsed = json.loads(output)
        assert parsed["score"] < 60
        assert parsed["summary"]["findings"]["high"] >= 1


class TestFormatText:
    def test_contains_header(self):
        result = scan_plugin(FIXTURES / "good-plugin")
        output = format_text(result)
        assert "Codex Plugin Scanner" in output
        assert "100/100" in output
        assert "Excellent" in output

    def test_contains_category_names(self):
        result = scan_plugin(FIXTURES / "good-plugin")
        output = format_text(result)
        assert "Manifest Validation" in output
        assert "Security" in output

    def test_contains_final_score_line(self):
        result = scan_plugin(FIXTURES / "good-plugin")
        output = format_text(result)
        assert "Final Score" in output

    def test_bad_plugin_output(self):
        result = scan_plugin(FIXTURES / "bad-plugin")
        output = format_text(result)
        assert "38/100" in output
        assert "Failing" in output


class TestMain:
    def test_returns_0_for_good_plugin(self):
        rc = main([str(FIXTURES / "good-plugin")])
        assert rc == 0

    def test_returns_0_by_default(self):
        rc = main([str(FIXTURES / "bad-plugin")])
        assert rc == 0

    def test_returns_1_for_score_below_min(self):
        rc = main([str(FIXTURES / "bad-plugin"), "--min-score", "50"])
        assert rc == 1

    def test_returns_0_when_score_meets_min(self):
        rc = main([str(FIXTURES / "good-plugin"), "--min-score", "50"])
        assert rc == 0

    def test_returns_1_for_nonexistent_dir(self):
        rc = main(["/nonexistent/path/that/does/not/exist"])
        assert rc == 1

    def test_returns_0_for_file_not_dir(self):
        rc = main([str(FIXTURES / "good-plugin" / "README.md")])
        assert rc == 1

    def test_json_flag(self, capsys):
        main([str(FIXTURES / "good-plugin"), "--json"])
        output = capsys.readouterr().out
        parsed = json.loads(output)
        assert parsed["score"] == 100

    def test_output_flag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "report.json"
            main([str(FIXTURES / "good-plugin"), "--output", str(out_file)])
            content = out_file.read_text(encoding="utf-8")
            parsed = json.loads(content)
            assert parsed["score"] == 100

    def test_min_score_boundary(self):
        rc = main([str(FIXTURES / "bad-plugin"), "--min-score", "38"])
        assert rc == 0

    def test_min_score_just_above(self):
        rc = main([str(FIXTURES / "bad-plugin"), "--min-score", "39"])
        assert rc == 1

    def test_version_flag(self, capsys):
        import contextlib

        with contextlib.suppress(SystemExit):
            main(["--version"])

    def test_text_mode_with_min_score_failure(self, capsys):
        main([str(FIXTURES / "bad-plugin"), "--min-score", "50"])
        captured = capsys.readouterr()
        # Should still produce text output
        assert "38/100" in captured.out

    def test_min_score_exact_boundary(self):
        # At exact boundary should pass (>=)
        rc = main([str(FIXTURES / "good-plugin"), "--min-score", "100"])
        assert rc == 0
