"""Tests for rare edge cases to hit remaining coverage branches."""

import tempfile
from pathlib import Path
from unittest.mock import patch

from codex_plugin_scanner.cli import format_text
from codex_plugin_scanner.scanner import scan_plugin

FIXTURES = Path(__file__).parent / "fixtures"


class TestRichOutputBranch:
    """Test plain text formatting output."""

    def test_format_text_returns_string(self):
        result = scan_plugin(FIXTURES / "good-plugin")
        output = format_text(result)
        assert isinstance(output, str)
        assert "100/100" in output

    def test_format_text_fallback(self):
        """Formatting remains stable even if rich is unavailable."""
        result = scan_plugin(FIXTURES / "good-plugin")
        with patch.dict("sys.modules", {"rich": None}):
            output = format_text(result)
            assert isinstance(output, str)
            assert "100/100" in output


class TestOSErrorBranches:
    """Test branches that handle file read errors."""

    def test_skill_frontmatter_oserror(self):
        from codex_plugin_scanner.checks.best_practices import check_skill_frontmatter

        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            manifest_dir = d / ".codex-plugin"
            manifest_dir.mkdir()
            (manifest_dir / "plugin.json").write_text(
                '{"name":"t","version":"1.0.0","description":"t","skills":"skills"}'
            )
            skills_dir = d / "skills" / "bad"
            skills_dir.mkdir(parents=True)
            (skills_dir / "SKILL.md").write_text("content")

            with patch("pathlib.Path.read_text", side_effect=OSError("Permission denied")):
                r = check_skill_frontmatter(d)
                assert r.passed

    def test_code_quality_eval_oserror(self):
        from codex_plugin_scanner.checks.code_quality import check_no_eval

        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "evil.py").write_text("eval(x)")
            with patch("pathlib.Path.read_text", side_effect=OSError("Permission denied")):
                r = check_no_eval(d)
                assert r.passed

    def test_code_quality_shell_injection_oserror(self):
        from codex_plugin_scanner.checks.code_quality import check_no_shell_injection

        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "evil.py").write_text("eval(x)")
            with patch("pathlib.Path.read_text", side_effect=OSError("Permission denied")):
                r = check_no_shell_injection(d)
                assert r.passed

    def test_license_oserror(self):
        from codex_plugin_scanner.checks.security import check_license

        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "LICENSE").write_text("text")
            with patch("pathlib.Path.read_text", side_effect=OSError("Permission denied")):
                r = check_license(d)
                assert not r.passed
                assert "could not be read" in r.message

    def test_mcp_oserror(self):
        from codex_plugin_scanner.checks.security import check_no_dangerous_mcp

        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / ".mcp.json").write_text("{}")
            with patch("pathlib.Path.read_text", side_effect=OSError("Permission denied")):
                r = check_no_dangerous_mcp(d)
                assert r.passed
                assert not r.applicable


class TestSecurityEdgeCases:
    def test_multiple_secret_files_truncation(self):
        from codex_plugin_scanner.checks.security import check_no_hardcoded_secrets

        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            for i in range(7):
                (d / f"secret{i}.txt").write_text(f'password = "longsecretvalue{i}"')
            r = check_no_hardcoded_secrets(d)
            assert not r.passed
            assert "and 2 more" in r.message

    def test_unknown_license_type(self):
        from codex_plugin_scanner.checks.security import check_license

        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "LICENSE").write_text("Custom license text here.")
            r = check_license(d)
            assert r.passed
            assert r.message == "LICENSE found"

    def test_safe_mcp(self):
        from codex_plugin_scanner.checks.security import check_no_dangerous_mcp

        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / ".mcp.json").write_text('{"mcpServers":{"safe":{"command":"echo","args":["hello"]}}}')
            r = check_no_dangerous_mcp(d)
            assert r.passed

    def test_secrets_oserror_in_file_scan(self):
        from codex_plugin_scanner.checks.security import check_no_hardcoded_secrets

        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "test.txt").write_text('password = "longpassword"')
            with patch("pathlib.Path.read_text", side_effect=OSError("Permission denied")):
                r = check_no_hardcoded_secrets(d)
                assert r.passed


class TestCodeQualityEdgeCases:
    def test_eval_and_function_in_same_file(self):
        from codex_plugin_scanner.checks.code_quality import check_no_eval

        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "bad.py").write_text("eval(x)\nnew Function(y)")
            r = check_no_eval(d)
            assert not r.passed
            assert "eval()" in r.message
            assert "Function()" in r.message

    def test_shell_injection_detected(self):
        from codex_plugin_scanner.checks.code_quality import check_no_shell_injection

        r = check_no_shell_injection(FIXTURES / "code-quality-bad")
        assert not r.passed
