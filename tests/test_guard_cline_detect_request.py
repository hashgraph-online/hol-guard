"""The request the Cline detection facade sends the native resident, and what it keeps for itself."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import cline, cline_detection
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline_mcp import cline_mcp_settings_candidates
from codex_plugin_scanner.guard.aibom_detection import NativeAibomError, _artifact_from_wire
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = tmp_path / "work"
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=tmp_path / "guard-home")


def _wire(artifact_id: str, artifact_type: str, **fields: object) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "name": artifact_id,
        "harness": "cline",
        "artifact_type": artifact_type,
        "source_scope": "global",
        "config_path": "/config",
        "command": None,
        "args": [],
        "url": None,
        "transport": None,
        "publisher": None,
        "metadata": {},
        **fields,
    }


def _host(artifact_id: str, **metadata: object) -> GuardArtifact:
    wire = _wire(artifact_id, "harness_host", metadata=metadata, config_path=f"/hosts/{artifact_id}")
    return _artifact_from_wire(wire)


def test_native_inventory_sends_the_resolved_settings_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[tuple[str, dict[str, object]]] = []

    def fake_native(kind: str, request: dict[str, object]):
        sent.append((kind, request))
        return (), (), ()

    monkeypatch.setattr(cline_detection, "native_adapter_detection_with_warnings", fake_native)
    context = _context(tmp_path)
    explicit = tmp_path / "elsewhere" / "settings.json"
    monkeypatch.setenv("CLINE_MCP_SETTINGS_PATH", str(explicit))
    monkeypatch.delenv("CLINE_DATA_DIR", raising=False)
    monkeypatch.delenv("CLINE_DIR", raising=False)

    cline_detection.native_cline_inventory(context, cline_mcp_settings_candidates(context))
    cline_detection.native_cline_inventory(context, ())

    (kind, request), (_kind, bare) = sent
    assert kind == "cline_detect"
    assert request["harness"] == "cline"
    assert request["home"] == str(context.home_dir)
    assert request["workspace"] == str(context.workspace_dir)
    assert isinstance(request["cwd"], str)
    settings = request["mcp_settings"]
    assert isinstance(settings, list)
    assert settings[0] == str(explicit)
    assert settings == [str(path) for path in cline_mcp_settings_candidates(context)]
    assert len(settings) == len(set(settings)) == 6
    assert bare["mcp_settings"] == []


def test_hosts_come_from_the_native_host_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifacts = (
        _host("cline:host:vscode:3.1.0", surface="vscode", version="3.1.0"),
        _host("cline:host:vscode:3.2.0", surface="vscode", version="3.2.0"),
        _host("cline:host:jetbrains:0", surface="jetbrains", protection_status="unverified"),
        _artifact_from_wire(_wire("cline:global:server", "mcp_server")),
    )
    monkeypatch.setattr(cline_detection, "native_adapter_detection_with_warnings", lambda *_: (artifacts, (), ()))
    monkeypatch.setattr(cline_detection, "_resolve_command", lambda *_: None)

    hosts = cline_detection.detect_cline_hosts(_context(tmp_path))

    assert hosts == cline_detection.ClineHostDetection(
        cli_executable=None,
        cli_version=None,
        vscode_versions=("3.1.0", "3.2.0"),
        jetbrains_paths=("/hosts/cline:host:jetbrains:0",),
    )
    assert hosts.hosts == ("vscode", "jetbrains")


def test_detect_merges_the_native_inventory_with_the_python_owned_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = _artifact_from_wire(_wire("cline:global:server", "mcp_server", name="server"))
    native = (
        (_host("cline:host:jetbrains:0", surface="jetbrains"), server),
        ("/home/.cline/data/settings/cline_mcp_settings.json", "/home/.cline/hooks"),
        ("Cline JetBrains was detected, but Guard does not mark that IDE protected.",),
    )
    firewalled: list[str] = []

    def firewall(artifact: GuardArtifact) -> GuardArtifact:
        firewalled.append(artifact.artifact_id)
        return artifact

    monkeypatch.setattr(cline, "native_cline_inventory", lambda *_: native)
    monkeypatch.setattr(cline, "resolve_cline_cli", lambda _context: ("/usr/local/bin/cline", "2.0.1"))
    monkeypatch.setattr(cline, "enrich_artifact_with_mcp_skill_firewall", firewall)
    monkeypatch.setattr(cline, "cline_native_hook_state", lambda _context: {"installed": True})
    monkeypatch.setattr(cline, "cline_plugin_state", lambda _context: {"installed": True})

    detection = cline.ClineHarnessAdapter().detect(_context(tmp_path))

    assert isinstance(detection, HarnessDetection)
    assert detection.installed is True
    assert detection.command_available is True
    assert detection.config_paths == native[1]
    assert [artifact.artifact_id for artifact in detection.artifacts] == [
        "cline:host:cli",
        "cline:host:jetbrains:0",
        "cline:global:server",
    ]
    assert detection.artifacts[0].metadata == {"version": "2.0.1", "surface": "cli"}
    assert detection.artifacts[0].command == "/usr/local/bin/cline"
    assert detection.artifacts[0].config_path == "/usr/local/bin"
    assert firewalled == ["cline:host:jetbrains:0", "cline:global:server"]
    assert detection.warnings[0].startswith("Guard found both managed Cline enforcement transports.")
    assert detection.warnings[1:] == native[2]


def test_detect_reports_nothing_installed_when_the_native_inventory_is_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cline, "native_cline_inventory", lambda *_: ((), (), ()))
    monkeypatch.setattr(cline, "resolve_cline_cli", lambda _context: (None, None))
    monkeypatch.setattr(cline, "cline_native_hook_state", lambda _context: {})
    monkeypatch.setattr(cline, "cline_plugin_state", lambda _context: {})

    detection = cline.ClineHarnessAdapter().detect(_context(tmp_path))

    assert (detection.installed, detection.command_available) == (False, False)
    assert detection.artifacts == () and detection.config_paths == () and detection.warnings == ()


def test_resolved_executable_never_asks_the_native_resident(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def unreachable(*_args: object) -> object:
        raise AssertionError("the CLI lookup is Python's")

    monkeypatch.setattr(cline_detection, "native_adapter_detection_with_warnings", unreachable)
    monkeypatch.setattr(cline_detection, "_resolve_command", lambda *_: "/opt/cline")
    monkeypatch.setattr(cline_detection, "_run_command_probe", lambda *_args, **_kwargs: {"stdout": "cline 4.5.6\n"})

    adapter = cline.ClineHarnessAdapter()

    assert adapter.resolved_executable(_context(tmp_path)) == "/opt/cline"
    assert cline_detection.resolve_cline_cli(_context(tmp_path)) == ("/opt/cline", "4.5.6")


def test_native_mcp_artifact_keeps_its_private_arguments_and_environment() -> None:
    wire = _wire(
        "cline:global:server",
        "mcp_server",
        args=["--token=*****"],
        runtime_private_metadata={"mcp_args": ["--token=abc"], "mcp_env": {"TOKEN": "secret"}},
    )

    artifact = _artifact_from_wire(wire)

    assert artifact.args == ("--token=*****",)
    assert artifact.runtime_private_metadata == {"mcp_args": ("--token=abc",), "mcp_env": {"TOKEN": "secret"}}
    assert "secret" not in repr(artifact) and "secret" not in str(artifact.to_dict())
    assert _artifact_from_wire(_wire("cline:host:cli", "harness_host")).runtime_private_metadata == {}


@pytest.mark.parametrize(
    "private",
    [
        [],
        "private",
        {},
        {"mcp_args": []},
        {"mcp_env": {}},
        {"mcp_args": "--x", "mcp_env": {}},
        {"mcp_args": [1], "mcp_env": {}},
        {"mcp_args": [], "mcp_env": []},
        {"mcp_args": [], "mcp_env": {"KEY": 1}},
        {"mcp_args": [], "mcp_env": {}, "extra": 1},
    ],
)
def test_malformed_private_metadata_is_refused(private: object) -> None:
    with pytest.raises(NativeAibomError, match="native_runner_authority_result_invalid"):
        _artifact_from_wire(_wire("cline:global:server", "mcp_server", runtime_private_metadata=private))
