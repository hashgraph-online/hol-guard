"""Tests for runtime verification engine."""

import os
from pathlib import Path

from codex_plugin_scanner import verification as verification_module
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


def test_verify_plugin_reports_real_workspace_path() -> None:
    result = verify_plugin(FIXTURES / "good-plugin")
    assert Path(result.workspace).exists()
    assert Path(result.workspace) == (FIXTURES / "good-plugin").resolve()


def test_verify_plugin_checks_skill_frontmatter_from_manifest(tmp_path: Path):
    (tmp_path / ".codex-plugin").mkdir()
    (tmp_path / ".codex-plugin" / "plugin.json").write_text(
        '{"name":"demo","version":"1.0.0","description":"demo","skills":"skills"}',
        encoding="utf-8",
    )
    (tmp_path / "skills" / "broken").mkdir(parents=True)
    (tmp_path / "skills" / "broken" / "SKILL.md").write_text("no frontmatter", encoding="utf-8")

    result = verify_plugin(tmp_path)

    assert result.verify_pass is False
    assert any(case.component == "skills" and case.classification == "frontmatter" for case in result.cases)


def test_verify_plugin_stdio_inherits_process_environment(tmp_path: Path, monkeypatch):
    captured_env: dict[str, str] = {}

    class StubProcess:
        returncode = 0

        def __init__(self):
            self.stdin = None

        def communicate(self, timeout: int):
            return "{}", ""

    def fake_popen(*args, **kwargs):
        nonlocal captured_env
        captured_env = kwargs["env"]
        return StubProcess()

    monkeypatch.setattr(verification_module.subprocess, "Popen", fake_popen)
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers":{"demo":{"command":"python","args":["-c","print(1)"]}}}',
        encoding="utf-8",
    )

    verify_plugin(tmp_path)

    assert captured_env
    assert captured_env["PATH"] == os.environ["PATH"]


def test_verify_plugin_kills_stdio_process_on_runtime_exception(tmp_path: Path, monkeypatch):
    killed = False

    class StubStdin:
        def write(self, payload: str):
            return len(payload)

        def flush(self):
            raise BrokenPipeError("broken pipe")

    class StubProcess:
        returncode = None

        def __init__(self):
            self.stdin = StubStdin()

        def kill(self):
            nonlocal killed
            killed = True

    monkeypatch.setattr(verification_module.subprocess, "Popen", lambda *args, **kwargs: StubProcess())
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers":{"demo":{"command":"python","args":["-c","print(1)"]}}}',
        encoding="utf-8",
    )

    result = verify_plugin(tmp_path)

    assert killed is True
    assert result.verify_pass is False
    assert any(case.classification == "spawn-failure" for case in result.cases)


def test_doctor_report_filters_component():
    report = build_doctor_report(FIXTURES / "good-plugin", "manifest")
    assert report["component"] == "manifest"
    assert isinstance(report["cases"], list)
