"""The request the Codex detection facade sends the native resident."""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.adapters import codex
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.models import HarnessDetection


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
        return {"artifacts": [], "found_paths": ["/seen"], "warnings": ["warned"]}

    monkeypatch.setattr(codex, "native_adapter_detection_payload", fake_native)
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
    assert all("config_legacy" not in entry and "hooks_legacy" not in entry for entry in sources)
    legacy = cast("dict[str, object]", request["legacy"])
    assert set(legacy) == {"expected", "argv", "legacy_argv", "statuses", "windows", "long_paths"}
    assert legacy["long_paths"] == {}

    pairs = codex.CodexHarnessAdapter._config_hook_pairs(context)
    captured = {path: None for pair in pairs for path in pair}
    captured[home / ".codex" / "config.toml"] = b'[mcp_servers.a]\ncommand = "x"\n'
    codex.CodexHarnessAdapter().detect(context, config_contents=captured)

    inline = sent[1][1]["contents"]
    assert inline[str(home / ".codex" / "config.toml")] == b'[mcp_servers.a]\ncommand = "x"\n'.hex()
    assert inline[str(work / ".codex" / "hooks.json")] is None


def _stub_detection(monkeypatch, sent: list[dict[str, object]]) -> None:
    def fake_native(_kind: str, request: dict[str, object]):
        sent.append(request)
        return {"artifacts": [], "found_paths": [], "warnings": []}

    monkeypatch.setattr(codex, "native_adapter_detection_payload", fake_native)
    monkeypatch.setattr(codex, "load_hook_manifest_baseline", lambda _spec: None)
    monkeypatch.setattr(codex, "_hook_manifest_spec", lambda _context: None)
    monkeypatch.setattr(codex, "extend_detection_with_workspace_aibom", lambda detection, **_kwargs: detection)
    monkeypatch.setattr(codex, "extend_codex_runtime_inventory", lambda detection, **_kwargs: detection)


def test_detect_reads_each_source_once_and_sends_those_bytes(tmp_path: Path, monkeypatch) -> None:
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

    codex.CodexHarnessAdapter().detect(context)

    assert reads.count(config) == 1
    assert sent[0]["contents"][str(config)] == b'[mcp_servers.a]\ncommand = "x"\n'.hex()


def test_detect_asks_for_results_spelled_the_way_the_context_did(tmp_path: Path, monkeypatch) -> None:
    sent: list[dict[str, object]] = []
    monkeypatch.chdir(tmp_path)
    anchored = str(tmp_path / "rel" / ".codex" / "config.toml")
    _stub_detection(monkeypatch, sent)
    context = HarnessContext(home_dir=Path("rel"), workspace_dir=Path("work"), guard_home=tmp_path / "guard")

    codex.CodexHarnessAdapter().detect(context)

    relative = str(Path("rel") / ".codex" / "config.toml")
    sources = cast("list[dict[str, str]]", sent[0]["sources"])
    assert sources[0]["config_path"] == anchored
    assert [anchored, relative] in cast("list[list[str]]", sent[0]["restore"])


def test_detect_expands_the_short_names_the_native_answer_asks_for(tmp_path: Path, monkeypatch) -> None:
    sent: list[dict[str, object]] = []
    answers = [
        {"reply": {"expand": [r"C:\PROGRA~1\py.exe"]}},
        {"artifacts": [], "found_paths": [], "warnings": []},
    ]

    def fake_native(_kind: str, request: dict[str, object]):
        sent.append(dict(cast("dict[str, object]", request["legacy"])))
        return answers.pop(0)

    _stub_detection(monkeypatch, [])
    monkeypatch.setattr(codex, "native_adapter_detection_payload", fake_native)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.codex_hook_command_line._long_path", lambda _name: r"C:\Program Files\py.exe"
    )
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")

    codex.CodexHarnessAdapter().detect(context)

    assert [entry["long_paths"] for entry in sent] == [
        {},
        {r"C:\PROGRA~1\py.exe": r"C:\Program Files\py.exe"},
    ]
