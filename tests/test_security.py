"""Tests for security checks."""

import tempfile
from pathlib import Path

from codex_plugin_scanner.checks.security import (
    _scan_all_files,
    check_license,
    check_mcp_transport_security,
    check_no_dangerous_mcp,
    check_no_hardcoded_secrets,
    check_security_md,
    run_security_checks,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestSecurityMd:
    def test_passes_when_found(self):
        r = check_security_md(FIXTURES / "good-plugin")
        assert r.passed and r.points == 3

    def test_fails_when_missing(self):
        r = check_security_md(FIXTURES / "minimal-plugin")
        assert not r.passed and r.points == 0


class TestLicense:
    def test_passes_for_apache(self):
        r = check_license(FIXTURES / "good-plugin")
        assert r.passed and r.points == 3

    def test_passes_for_apache_canonical_url(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "LICENSE").write_text(
                "Apache License\nSee https://www.apache.org/licenses/LICENSE-2.0 for the full text.\n"
            )
            r = check_license(d)
            assert r.passed and r.points == 3
            assert r.message == "LICENSE found (Apache-2.0)"

    def test_does_not_treat_arbitrary_apache_hostname_text_as_canonical_license(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "LICENSE").write_text("Apache project notes mentioning www.apache.org are included here.")
            r = check_license(d)
            assert r.passed and r.points == 3
            assert r.message == "LICENSE found"

    def test_passes_for_mit(self):
        r = check_license(FIXTURES / "mit-license")
        assert r.passed and r.points == 3
        assert "MIT" in r.message

    def test_fails_when_missing(self):
        r = check_license(FIXTURES / "minimal-plugin")
        assert not r.passed and r.points == 0


class TestNoHardcodedSecrets:
    def test_passes_clean_dir(self):
        r = check_no_hardcoded_secrets(FIXTURES / "good-plugin")
        assert r.passed and r.points == 7

    def test_fails_with_secrets(self):
        r = check_no_hardcoded_secrets(FIXTURES / "bad-plugin")
        assert not r.passed and r.points == 0
        assert "secrets.js" in r.message

    def test_message_lists_file(self):
        r = check_no_hardcoded_secrets(FIXTURES / "bad-plugin")
        assert "secrets.js" in r.message

    def test_handles_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            r = check_no_hardcoded_secrets(Path(tmpdir))
            assert r.passed and r.points == 7


class TestNoDangerousMcp:
    def test_passes_when_no_mcp(self):
        r = check_no_dangerous_mcp(FIXTURES / "good-plugin")
        assert r.passed and r.points == 0
        assert not r.applicable

    def test_fails_with_dangerous_commands(self):
        r = check_no_dangerous_mcp(FIXTURES / "bad-plugin")
        assert not r.passed and r.points == 0

    def test_passes_when_mcp_is_safe(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mcp = Path(tmpdir) / ".mcp.json"
            mcp.write_text('{"mcpServers":{"safe":{"command":"echo","args":["hello"]}}}')
            r = check_no_dangerous_mcp(Path(tmpdir))
            assert r.passed and r.points == 4


class TestMcpTransportSecurity:
    def test_not_applicable_for_stdio_only_configs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mcp = Path(tmpdir) / ".mcp.json"
            mcp.write_text('{"mcpServers":{"safe":{"command":"echo","args":["hello"]}}}', encoding="utf-8")
            r = check_mcp_transport_security(Path(tmpdir))
            assert r.passed and r.points == 0
            assert not r.applicable

    def test_passes_for_https_remote_transport(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mcp = Path(tmpdir) / ".mcp.json"
            mcp.write_text('{"mcpServers":{"safe":{"url":"https://example.com/mcp"}}}', encoding="utf-8")
            r = check_mcp_transport_security(Path(tmpdir))
            assert r.passed and r.points == 4

    def test_fails_for_insecure_remote_transport(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mcp = Path(tmpdir) / ".mcp.json"
            mcp.write_text('{"mcpServers":{"unsafe":{"url":"http://0.0.0.0:8080/mcp"}}}', encoding="utf-8")
            r = check_mcp_transport_security(Path(tmpdir))
            assert not r.passed and r.points == 0

    def test_passes_for_loopback_remote_transport(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mcp = Path(tmpdir) / ".mcp.json"
            mcp.write_text('{"mcpServers":{"safe":{"url":"http://127.0.0.2:8080/mcp"}}}', encoding="utf-8")
            r = check_mcp_transport_security(Path(tmpdir))
            assert r.passed and r.points == 4

    def test_ignores_metadata_urls_when_collecting_transport_endpoints(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mcp = Path(tmpdir) / ".mcp.json"
            mcp.write_text(
                ('{"mcpServers":{"safe":{"command":"echo","metadata":{"homepage":{"url":"http://example.com"}}}}}'),
                encoding="utf-8",
            )
            r = check_mcp_transport_security(Path(tmpdir))
            assert r.passed and r.points == 0
            assert not r.applicable

    def test_fails_for_invalid_mcp_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mcp = Path(tmpdir) / ".mcp.json"
            mcp.write_text("{invalid", encoding="utf-8")
            r = check_mcp_transport_security(Path(tmpdir))
            assert not r.passed and r.points == 0
            assert r.max_points == 4
            assert r.findings[0].rule_id == "MCP_CONFIG_INVALID_JSON"


class TestScanAllFiles:
    def test_skips_excluded_dirs(self):
        files = _scan_all_files(FIXTURES / "good-plugin")
        paths = [str(f) for f in files]
        for p in paths:
            assert "node_modules" not in p
            assert ".git" not in p

    def test_skips_binary_files(self):
        files = _scan_all_files(FIXTURES / "good-plugin")
        binary_exts = {".png", ".jpg", ".wasm", ".lock"}
        for f in files:
            assert f.suffix.lower() not in binary_exts

    def test_returns_list_of_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test.txt").write_text("hello")
            files = _scan_all_files(Path(tmpdir))
            assert len(files) == 1
            assert files[0].name == "test.txt"


class TestRunSecurityChecks:
    def test_good_plugin_gets_16(self):
        results = run_security_checks(FIXTURES / "good-plugin")
        assert sum(c.points for c in results) == 16
        assert sum(c.max_points for c in results) == 16

    def test_bad_plugin_detects_issues(self):
        results = run_security_checks(FIXTURES / "bad-plugin")
        names = {c.name: c.passed for c in results}
        assert names["No hardcoded secrets"] is False
        assert names["No dangerous MCP commands"] is False

    def test_minimal_plugin_partial(self):
        results = run_security_checks(FIXTURES / "minimal-plugin")
        total = sum(c.points for c in results)
        assert 0 < total < 16

    def test_returns_tuple_of_correct_length(self):
        results = run_security_checks(FIXTURES / "good-plugin")
        assert isinstance(results, tuple)
        assert len(results) == 6
