"""The request the Codex detection facade sends the native resident."""

from __future__ import annotations

import datetime
import os
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard import codex_harness_lifecycle as codex_lifecycle
from codex_plugin_scanner.guard.harness.base import HarnessContext
from codex_plugin_scanner.guard.models import HarnessDetection
from codex_plugin_scanner.guard.native_codex_hook_identity import wire_codex_hook_bindings


def test_wire_bindings_drop_values_json_cannot_carry() -> None:
    keep = {"event": "Stop", "group": {"matcher": None}, "handler": {"command": "a", "timeout": 3}}
    stamp = {"event": "Stop", "group": {}, "handler": {"command": "b", "when": datetime.datetime(2020, 1, 1)}}
    nan = {"event": "Stop", "group": {}, "handler": {"command": "c", "ratio": float("nan")}}

    wire = wire_codex_hook_bindings([keep, stamp, nan])

    assert wire == [keep]
    assert wire[0] is not keep


def test_detect_sends_scoped_sources_and_inline_captures(tmp_path: Path, monkeypatch) -> None:
    sent: list[tuple[str, dict[str, object]]] = []

    def fake_native(kind: str, request: dict[str, object]):
        sent.append((kind, request))
        return {"artifacts": [], "found_paths": ["/seen"], "warnings": ["warned"]}

    monkeypatch.setattr(codex_lifecycle, "native_adapter_detection_payload", fake_native)
    monkeypatch.setattr(codex_lifecycle, "load_hook_manifest_baseline", lambda _spec: None)
    monkeypatch.setattr(codex_lifecycle, "_hook_manifest_spec", lambda _context: None)
    monkeypatch.setattr(
        codex_lifecycle, "extend_detection_with_workspace_aibom", lambda detection, **_kwargs: detection
    )
    monkeypatch.setattr(codex_lifecycle, "extend_codex_runtime_inventory", lambda detection, **_kwargs: detection)
    home = tmp_path / "home"
    work = tmp_path / "work"
    context = HarnessContext(home_dir=home, workspace_dir=work, guard_home=tmp_path / "guard")
    (home / ".codex").mkdir(parents=True)
    (home / ".codex" / "config.toml").write_text('[mcp_servers.a]\ncommand = "x"\n', encoding="utf-8")

    detection = codex_lifecycle.CodexHarnessAdapter().detect(context)

    assert isinstance(detection, HarnessDetection)
    assert detection.config_paths == ("/seen",)
    assert detection.warnings == ("warned",)
    kind, request = sent[0]
    assert kind == "codex_detect"
    assert request["harness"] == "codex"
    assert request["authenticated_bindings"] == []
    assert "contents" not in request
    pairs = cast("list[dict[str, str]]", request["pairs"])
    assert [(entry["scope"], entry["config"], entry["hooks"]) for entry in pairs] == [
        ("global", str(home / ".codex" / "config.toml"), str(home / ".codex" / "hooks.json")),
        ("project", str(work / ".codex" / "config.toml"), str(work / ".codex" / "hooks.json")),
    ]
    assert request["authenticated_config"] == str(home / ".codex" / "config.toml")
    assert request["cwd"] == os.getcwd()
    assert not {"sources", "restore"} & set(request)
    legacy = cast("dict[str, object]", request["legacy"])
    assert set(legacy) == {"expected", "argv", "legacy_argv", "statuses", "windows", "long_paths"}
    assert legacy["long_paths"] == {}

    pairs = codex_lifecycle.CodexHarnessAdapter._config_hook_pairs(context)
    captured = {path: None for pair in pairs for path in pair}
    captured[home / ".codex" / "config.toml"] = b'[mcp_servers.a]\ncommand = "x"\n'
    codex_lifecycle.CodexHarnessAdapter().detect(context, config_contents=captured)

    inline = sent[1][1]["contents"]
    assert inline[str(home / ".codex" / "config.toml")] == b'[mcp_servers.a]\ncommand = "x"\n'.hex()
    assert inline[str(work / ".codex" / "hooks.json")] is None


def _stub_detection(monkeypatch, sent: list[dict[str, object]]) -> None:
    def fake_native(_kind: str, request: dict[str, object]):
        sent.append(request)
        return {"artifacts": [], "found_paths": [], "warnings": []}

    monkeypatch.setattr(codex_lifecycle, "native_adapter_detection_payload", fake_native)
    monkeypatch.setattr(codex_lifecycle, "load_hook_manifest_baseline", lambda _spec: None)
    monkeypatch.setattr(codex_lifecycle, "_hook_manifest_spec", lambda _context: None)
    monkeypatch.setattr(
        codex_lifecycle, "extend_detection_with_workspace_aibom", lambda detection, **_kwargs: detection
    )
    monkeypatch.setattr(codex_lifecycle, "extend_codex_runtime_inventory", lambda detection, **_kwargs: detection)


def test_detect_without_a_capture_leaves_the_reading_to_the_runtime(tmp_path: Path, monkeypatch) -> None:
    sent: list[dict[str, object]] = []
    _stub_detection(monkeypatch, sent)
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

    codex_lifecycle.CodexHarnessAdapter().detect(context)

    assert config not in reads
    assert "contents" not in sent[0]


def test_detect_sends_the_context_spelling_and_the_process_directory(tmp_path: Path, monkeypatch) -> None:
    sent: list[dict[str, object]] = []
    monkeypatch.chdir(tmp_path)
    _stub_detection(monkeypatch, sent)
    context = HarnessContext(home_dir=Path("rel"), workspace_dir=Path("work"), guard_home=tmp_path / "guard")

    codex_lifecycle.CodexHarnessAdapter().detect(context)

    relative = str(Path("rel") / ".codex" / "config.toml")
    pairs = cast("list[dict[str, str]]", sent[0]["pairs"])
    assert pairs[0]["config"] == relative
    assert sent[0]["authenticated_config"] == relative
    # The runtime anchors the sources to this directory and restores the spelling.
    assert sent[0]["cwd"] == os.getcwd()
