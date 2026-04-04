"""Tests for runtime verification engine."""

import json
import os
import sys
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


def test_verify_plugin_stdio_inherits_process_environment(tmp_path: Path, monkeypatch):
    captured_env: dict[str, str] = {}

    class StubInput:
        def __init__(self):
            self.writes: list[str] = []

        def write(self, payload: str):
            self.writes.append(payload)
            return len(payload)

        def flush(self):
            return None

        def close(self):
            return None

    class StubOutput:
        def __init__(self, lines: list[str]):
            self._lines = lines

        def readline(self):
            return self._lines.pop(0) if self._lines else ""

        def read(self):
            return ""

    class StubProcess:
        returncode = 0

        def __init__(self):
            self.stdin = StubInput()
            self.stdout = StubOutput(
                [
                    '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"stub","version":"1.0.0"}}}\n'
                ]
            )
            self.stderr = StubOutput([])

        def wait(self, timeout: int):
            return 0

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
            self.stdout = None
            self.stderr = None

        def kill(self):
            nonlocal killed
            killed = True

        def poll(self):
            return None

        def wait(self, timeout=None):
            return None

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


def test_verify_plugin_performs_mcp_initialize_lifecycle(tmp_path: Path):
    script = """
import json
import sys

init = json.loads(sys.stdin.readline())
assert init["method"] == "initialize"
assert init["params"]["protocolVersion"]
assert init["params"]["clientInfo"]["name"] == "codex-plugin-scanner"
sys.stdout.write(json.dumps({
    "jsonrpc": "2.0",
    "id": init["id"],
    "result": {
        "protocolVersion": init["params"]["protocolVersion"],
        "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
        "serverInfo": {"name": "stub", "version": "1.0.0"}
    }
}) + "\\n")
sys.stdout.flush()

initialized = json.loads(sys.stdin.readline())
assert initialized["method"] == "notifications/initialized"

for method, key in (("tools/list", "tools"), ("resources/list", "resources"), ("prompts/list", "prompts")):
    request = json.loads(sys.stdin.readline())
    assert request["method"] == method
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": {key: []}}) + "\\n")
    sys.stdout.flush()
"""
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
                        "command": sys.executable,
                        "args": ["-u", "-c", script],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    result = verify_plugin(tmp_path)
    report = build_doctor_report(tmp_path, "mcp")

    assert result.verify_pass is True
    assert any(case.name == "stdio initialize:stub" and case.passed for case in result.cases)
    assert "notifications/initialized" in report["stdout_log"]
    assert "tools/list" in report["stdout_log"]
