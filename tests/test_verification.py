"""Tests for runtime verification engine."""

import json
from pathlib import Path

from codex_plugin_scanner.verification import build_doctor_report, verify_plugin

FIXTURES = Path(__file__).parent / "fixtures"


def test_verify_plugin_passes_for_good_fixture():
    result = verify_plugin(FIXTURES / "good-plugin")
    assert result.verify_pass is True


def test_verify_plugin_fails_for_insecure_remote(tmp_path: Path):
    (tmp_path / ".mcp.json").write_text('{"remotes":[{"url":"http://example.com"}]}', encoding="utf-8")
    result = verify_plugin(tmp_path)
    assert result.verify_pass is False


def test_verify_plugin_handles_non_object_marketplace_payload(tmp_path: Path):
    (tmp_path / "marketplace.json").write_text('["not-an-object"]', encoding="utf-8")
    result = verify_plugin(tmp_path)
    assert result.verify_pass is False
    assert any(case.component == "marketplace" and case.classification == "schema" for case in result.cases)


def test_verify_plugin_marketplace_repo_checks_all_local_plugins():
    fixtures = Path(__file__).parent / "fixtures"
    result = verify_plugin(fixtures / "multi-plugin-repo")

    assert result.scope == "repository"
    assert result.verify_pass is False
    assert len(result.plugin_results) == 2
    assert {plugin.plugin_name for plugin in result.plugin_results} == {"alpha-plugin", "beta-plugin"}
    assert any(case.name.startswith("alpha-plugin · ") for case in result.cases)
    assert any(case.name.startswith("beta-plugin · ") for case in result.cases)
    assert any(skip.name == "remote-plugin" for skip in result.skipped_targets)


def test_verify_plugin_reports_real_workspace_path() -> None:
    result = verify_plugin(FIXTURES / "good-plugin")
    assert Path(result.workspace).exists()
    assert Path(result.workspace) == (FIXTURES / "good-plugin").resolve()


def test_verify_plugin_checks_skill_frontmatter_from_manifest(tmp_path: Path):
    (tmp_path / ".codex-plugin").mkdir()
    (tmp_path / ".codex-plugin" / "plugin.json").write_text(
        '{"name":"demo","version":"1.0.0","description":"demo","skills":"./skills"}',
        encoding="utf-8",
    )
    (tmp_path / "skills" / "broken").mkdir(parents=True)
    (tmp_path / "skills" / "broken" / "SKILL.md").write_text("no frontmatter", encoding="utf-8")

    result = verify_plugin(tmp_path)

    assert result.verify_pass is False
    assert any(case.component == "skills" and case.classification == "frontmatter" for case in result.cases)


def test_verify_plugin_skips_stdio_execution_for_untrusted_servers(tmp_path: Path):
    (tmp_path / ".codex-plugin").mkdir()
    (tmp_path / ".codex-plugin" / "plugin.json").write_text(
        '{"name":"demo","version":"1.0.0","description":"demo"}',
        encoding="utf-8",
    )
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers":{"demo":{"command":"python","args":["-c","print(1)"]}}}',
        encoding="utf-8",
    )

    result = verify_plugin(tmp_path)

    assert result.verify_pass is False
    assert any(case.name == "stdio execution:demo" for case in result.cases)
    assert any(case.classification == "safety-skip" for case in result.cases)
    assert all(not trace.name.startswith("stdio") for trace in result.traces)


def test_verify_plugin_reports_stdio_servers_without_spawning_them(tmp_path: Path):
    (tmp_path / ".codex-plugin").mkdir()
    (tmp_path / ".codex-plugin" / "plugin.json").write_text(
        '{"name":"demo","version":"1.0.0","description":"demo"}',
        encoding="utf-8",
    )
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers":{"demo":{"command":"python","args":["-c","print(1)"]}}}',
        encoding="utf-8",
    )

    result = verify_plugin(tmp_path)

    assert result.verify_pass is False
    expected_message = (
        "Skipped stdio command execution for safety; manual review is required before trusting it."
    )
    assert any(case.message == expected_message for case in result.cases)


def test_doctor_report_filters_component():
    report = build_doctor_report(FIXTURES / "good-plugin", "manifest")
    assert report["component"] == "manifest"
    assert isinstance(report["cases"], list)


def test_doctor_report_explains_when_stdio_execution_is_skipped(tmp_path: Path):
    (tmp_path / ".codex-plugin").mkdir()
    (tmp_path / ".codex-plugin" / "plugin.json").write_text(
        '{"name":"mcp-demo","version":"1.0.0","description":"demo"}',
        encoding="utf-8",
    )
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "stub": {
                        "command": "python",
                        "args": ["-u", "-c", "print('unsafe')"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    report = build_doctor_report(tmp_path, "mcp")

    assert report["verify_pass"] is False
    assert report["stdout_log"] == ""
    assert any(case["classification"] == "safety-skip" for case in report["cases"])
