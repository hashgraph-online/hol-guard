"""The request the Codex detection facade sends the native resident."""

from __future__ import annotations

import datetime
from pathlib import Path

from codex_plugin_scanner.guard.adapters import codex
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection


def test_wire_bindings_drop_values_json_cannot_carry() -> None:
    keep = {"event": "Stop", "group": {"matcher": None}, "handler": {"command": "a", "timeout": 3}}
    stamp = {"event": "Stop", "group": {}, "handler": {"command": "b", "when": datetime.datetime(2020, 1, 1)}}
    nan = {"event": "Stop", "group": {}, "handler": {"command": "c", "ratio": float("nan")}}

    wire = codex._wire_bindings([keep, stamp, nan])

    assert wire == [keep]
    assert wire[0] is not keep


def test_detect_sends_scoped_sources_and_inline_captures(tmp_path: Path, monkeypatch) -> None:
    sent: list[tuple[str, dict[str, object]]] = []

    def fake_native(kind: str, request: dict[str, object]):
        sent.append((kind, request))
        return (), ("/seen",), ("warned",)

    monkeypatch.setattr(codex, "native_adapter_detection_with_warnings", fake_native)
    monkeypatch.setattr(codex, "load_hook_manifest_baseline", lambda _spec: None)
    monkeypatch.setattr(codex, "_hook_manifest_spec", lambda _context: None)
    monkeypatch.setattr(codex, "extend_detection_with_workspace_aibom", lambda detection, **_kwargs: detection)
    monkeypatch.setattr(codex, "extend_codex_runtime_inventory", lambda detection, **_kwargs: detection)
    home = tmp_path / "home"
    work = tmp_path / "work"
    context = HarnessContext(home_dir=home, workspace_dir=work, guard_home=tmp_path / "guard")
    (home / ".codex").mkdir(parents=True)
    (home / ".codex" / "config.toml").write_text('[mcp_servers.a]\ncommand = "x"\n', encoding="utf-8")

    detection = codex.CodexHarnessAdapter().detect(context)

    assert isinstance(detection, HarnessDetection)
    assert detection.config_paths == ("/seen",)
    assert detection.warnings == ("warned",)
    kind, request = sent[0]
    assert kind == "codex_detect"
    assert request["harness"] == "codex"
    assert request["authenticated_bindings"] == []
    config_key = str(home / ".codex" / "config.toml")
    assert request["contents"][config_key] == b'[mcp_servers.a]\ncommand = "x"\n'.hex()
    assert request["contents"][str(work / ".codex" / "hooks.json")] is None
    sources = request["sources"]
    assert [(entry["config_scope"], entry["hooks_scope"], entry["authenticated"]) for entry in sources] == [
        ("global", "global", True),
        ("project", "project", False),
    ]
    assert sources[0]["config_path"] == str(home / ".codex" / "config.toml")
    assert sources[1]["hooks_path"] == str(work / ".codex" / "hooks.json")

    pairs = codex.CodexHarnessAdapter._config_hook_pairs(context)
    captured = {path: None for pair in pairs for path in pair}
    captured[home / ".codex" / "config.toml"] = b'[mcp_servers.a]\ncommand = "x"\n'
    codex.CodexHarnessAdapter().detect(context, config_contents=captured)

    inline = sent[1][1]["contents"]
    assert inline[str(home / ".codex" / "config.toml")] == b'[mcp_servers.a]\ncommand = "x"\n'.hex()
    assert inline[str(work / ".codex" / "hooks.json")] is None


def _stub_detection(monkeypatch, sent: list[dict[str, object]], result) -> None:
    def fake_native(_kind: str, request: dict[str, object]):
        sent.append(request)
        return result

    monkeypatch.setattr(codex, "native_adapter_detection_with_warnings", fake_native)
    monkeypatch.setattr(codex, "load_hook_manifest_baseline", lambda _spec: None)
    monkeypatch.setattr(codex, "_hook_manifest_spec", lambda _context: None)
    monkeypatch.setattr(codex, "extend_detection_with_workspace_aibom", lambda detection, **_kwargs: detection)
    monkeypatch.setattr(codex, "extend_codex_runtime_inventory", lambda detection, **_kwargs: detection)


def test_detect_reads_each_source_once_and_sends_those_bytes(tmp_path: Path, monkeypatch) -> None:
    sent: list[dict[str, object]] = []
    _stub_detection(monkeypatch, sent, ((), (), ()))
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    config = home / ".codex" / "config.toml"
    config.write_text('[mcp_servers.a]\ncommand = "x"\n', encoding="utf-8")
    reads: list[Path] = []
    original = Path.read_bytes

    def counting(self: Path) -> bytes:
        reads.append(self)
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", counting)
    context = HarnessContext(home_dir=home, workspace_dir=tmp_path / "work", guard_home=tmp_path / "guard")

    codex.CodexHarnessAdapter().detect(context)

    assert reads.count(config) == 1
    assert sent[0]["contents"][str(config)] == b'[mcp_servers.a]\ncommand = "x"\n'.hex()


def test_detect_spells_results_the_way_the_context_did(tmp_path: Path, monkeypatch) -> None:
    sent: list[dict[str, object]] = []
    monkeypatch.chdir(tmp_path)
    anchored = str(tmp_path / "rel" / ".codex" / "config.toml")
    artifact = GuardArtifact(
        artifact_id="codex:global:mcp:a",
        name="a",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="global",
        config_path=anchored,
        command="x",
        metadata={"paths": [anchored], "nested": {"config": anchored}, "other": "keep"},
    )
    _stub_detection(monkeypatch, sent, ((artifact,), (anchored,), (f"bad {anchored}",)))
    context = HarnessContext(home_dir=Path("rel"), workspace_dir=Path("work"), guard_home=tmp_path / "guard")

    detection = codex.CodexHarnessAdapter().detect(context)

    relative = str(Path("rel") / ".codex" / "config.toml")
    assert sent[0]["sources"][0]["config_path"] == anchored
    assert detection.config_paths == (relative,)
    assert detection.warnings == (f"bad {relative}",)
    restored = detection.artifacts[0]
    assert restored.config_path == relative
    assert restored.metadata == {"paths": [relative], "nested": {"config": relative}, "other": "keep"}
