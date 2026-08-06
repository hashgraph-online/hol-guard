"""Tests for security checks."""

import tempfile
from pathlib import Path

import pytest

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


def _symlink_or_skip(link_path: Path, target: Path) -> None:
    try:
        link_path.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are not supported in this environment")


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

    def test_detects_provider_specific_tokens_in_text_svg_and_lock_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            github_token = "".join(("github_", "pat_", "abcdefghij", "klmnopqrst", "uvwxyz0123", "456789_ABCD"))
            openai_token = "".join(("sk-", "proj-", "abcdefghij", "klmnopqrst", "uvwxyz0123", "456789ABCD"))
            slack_app_token = "".join(("xapp-", "1-", "abcdefghij", "klmnopqrst", "uvwxyz0123456789"))
            slack_user_token = "".join(("xoxe-", "1-", "abcdefghij", "klmnopqrst", "uvwxyz0123456789"))
            slack_config_token = "".join(("xoxr-", "1-", "abcdefghij", "klmnopqrst", "uvwxyz0123456789"))
            (root / "logo.svg").write_text(
                f"<svg><!-- {github_token} --></svg>",
                encoding="utf-8",
            )
            (root / "deps.lock").write_text(
                f'openai = "{openai_token}"\n'
                f'slack_app = "{slack_app_token}"\n'
                f'slack_user = "{slack_user_token}"\n'
                f'slack_config = "{slack_config_token}"\n',
                encoding="utf-8",
            )

            result = check_no_hardcoded_secrets(root)

            assert result.passed is False
            assert result.points == 0
            assert "logo.svg" in result.message
            assert "deps.lock" in result.message

    def test_ignores_placeholder_credentials_in_documentation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "README.md").write_text(
                'export JIRA_API_TOKEN="your-api-token"\n'
                'const apiKey = "sk-proj-xxxxx"\n'
                'export NUTRIENT_API_KEY="pdf_live_..."\n',
                encoding="utf-8",
            )

            result = check_no_hardcoded_secrets(root)

            assert result.passed is True

    def test_detects_real_looking_generic_secret_in_documentation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            jira_token = "".join(("A1b2C3d4", "E5f6G7h8", "I9j0K1l2"))
            (root / "README.md").write_text(
                f'export JIRA_API_TOKEN="{jira_token}"\n',
                encoding="utf-8",
            )

            result = check_no_hardcoded_secrets(root)

            assert result.passed is False
            assert result.findings[0].file_path == "README.md"
            assert result.findings[0].line_number == 1

    def test_ignores_synthetic_secret_sequences_in_test_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            tests_dir = root / "tests"
            tests_dir.mkdir()
            aws_token = "".join(("AKIA", "ABCDEFGH", "IJKLMNOP"))
            openai_token = "".join(("sk-proj-", "abcdefghij", "1234567890"))
            github_token = "".join(("ghp_", "abcdefghij", "klmnopqrst", "uvwxyz", "ABCDEFGHIJ"))
            (tests_dir / "secret_examples.test.js").write_text(
                "if (await test('detectSecrets finds provider tokens', async () => {\n"
                f"  const findings = detectSecrets('{aws_token} {openai_token} {github_token}');\n"
                "  assert.ok(findings.length > 0);\n"
                "})) passed += 1;\n",
                encoding="utf-8",
            )

            result = check_no_hardcoded_secrets(root)

            assert result.passed is True

    def test_detects_real_provider_secret_in_documentation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            openai_token = "".join(("sk-proj-", "A1b2C3d4", "E5f6G7h8", "I9j0K1l2"))
            (root / "README.md").write_text(
                f'const apiKey = "{openai_token}";\n',
                encoding="utf-8",
            )

            result = check_no_hardcoded_secrets(root)

            assert result.passed is False
            assert result.findings[0].line_number == 1

    def test_ignores_truncated_private_key_example_but_detects_full_block(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            pem_header = "-----BEGIN " + "RSA PRIVATE KEY-----"
            pem_footer = "-----END " + "RSA PRIVATE KEY-----"
            (root / "README.md").write_text(
                "Example:\n"
                f"{pem_header}\n"
                "MIIE...\n",
                encoding="utf-8",
            )
            assert check_no_hardcoded_secrets(root).passed is True

            (root / "README.md").write_text(
                f"{pem_header}\n"
                "MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuv==\n"
                f"{pem_footer}\n",
                encoding="utf-8",
            )

            result = check_no_hardcoded_secrets(root)

            assert result.passed is False
            assert result.findings[0].line_number == 1

    def test_detects_short_real_secret_in_documentation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "README.md").write_text('token = "realpass123"\n', encoding="utf-8")

            result = check_no_hardcoded_secrets(root)

            assert result.passed is False
            assert result.findings[0].line_number == 1

    def test_detects_placeholder_like_secret_in_source_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            src_dir = root / "src"
            src_dir.mkdir()
            (src_dir / "app.py").write_text('token = "prod-demo-A1b2C3d4"\n', encoding="utf-8")

            result = check_no_hardcoded_secrets(root)

            assert result.passed is False
            assert result.findings[0].file_path == "src/app.py"

    def test_detects_plain_provider_token_examples_without_illustrative_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            github_token = "".join(("ghp_", "abcdefghij", "klmnopqrst", "uvwxyz", "ABCDEFGHIJ"))
            (root / "README.md").write_text(f"{github_token}\n", encoding="utf-8")

            result = check_no_hardcoded_secrets(root)

            assert result.passed is False
            assert result.findings[0].file_path == "README.md"

    def test_detects_truncated_private_key_with_real_body(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            pem_header = "-----BEGIN " + "RSA PRIVATE KEY-----"
            (root / "README.md").write_text(
                f"{pem_header}\n"
                "MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuv==\n",
                encoding="utf-8",
            )

            result = check_no_hardcoded_secrets(root)

            assert result.passed is False
            assert result.findings[0].line_number == 1


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
        binary_exts = {".png", ".jpg", ".wasm"}
        for f in files:
            assert f.suffix.lower() not in binary_exts

    def test_keeps_text_svg_and_lock_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "logo.svg").write_text("<svg>safe</svg>", encoding="utf-8")
            (root / "deps.lock").write_text("package = 1\n", encoding="utf-8")

            files = _scan_all_files(root)
            names = {path.name for path in files}

            assert "logo.svg" in names
            assert "deps.lock" in names

    def test_returns_list_of_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test.txt").write_text("hello")
            files = _scan_all_files(Path(tmpdir))
            assert len(files) == 1
            assert files[0].name == "test.txt"

    def test_skips_symlinked_files_outside_root(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            outside = root.parent / "outside-secret.txt"
            outside.write_text('token = "super-secret-token"', encoding="utf-8")
            _symlink_or_skip(root / "linked-secret.txt", outside)
            files = _scan_all_files(root)
            assert files == []

    def test_hardcoded_secret_check_ignores_symlinked_files_outside_root(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            outside = root.parent / "outside-secret.js"
            outside.write_text('const token = "super-secret-token";', encoding="utf-8")
            _symlink_or_skip(root / "linked-secret.js", outside)
            result = check_no_hardcoded_secrets(root)
            assert result.passed is True


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
