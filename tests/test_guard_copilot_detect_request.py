"""The request the Copilot detection facade sends the native resident.

Every recorded vector carries the arguments the resident replays; the facade
must build exactly those for the same fixture tree, so the Rust replay covers
what production sends.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import copilot
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.models import GuardArtifact

VECTORS = (
    Path(__file__).resolve().parents[1] / "rust" / "crates" / "guard-runtime" / "testdata" / "copilot" / "vectors.json"
)
CASES = json.loads(VECTORS.read_text(encoding="utf-8"))["cases"]


def _materialize(root: Path, case: dict) -> None:
    (root / "work").mkdir(parents=True)
    (root / "home").mkdir()
    for entry in case["files"]:
        target = root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        data = bytes.fromhex(entry["hex"]) if "hex" in entry else entry["text"].encode("utf-8")
        target.write_bytes(data)
    for relative in case["dirs"]:
        (root / relative).mkdir(parents=True, exist_ok=True)
    for entry in case["symlinks"]:
        target = root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(entry["target"].replace("<ROOT>", str(root)))


def _substitute(value: object, root: str) -> object:
    return json.loads(json.dumps(value).replace("<ROOT>", root))


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_detect_sends_the_recorded_request(case: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[tuple[str, dict[str, object]]] = []

    def fake_native(kind: str, request: dict[str, object]):
        sent.append((kind, request))
        return (), (), ()

    monkeypatch.setattr(copilot, "native_adapter_detection_with_warnings", fake_native)
    root = tmp_path.resolve()
    _materialize(root, case)
    home = root / "home"
    context = HarnessContext(
        home_dir=home,
        workspace_dir=None if case["no_workspace"] else (home if case["workspace_is_home"] else root / "work"),
        guard_home=root / "guard-home",
    )
    args = _substitute(case["args"], str(root))
    contents = args.get("contents")
    captured = (
        None
        if contents is None
        else {Path(path): None if data is None else bytes.fromhex(data) for path, data in contents.items()}
    )

    copilot.CopilotHarnessAdapter().detect(context, config_contents=captured)

    assert sent == [("copilot_detect", args)]


def test_detect_returns_resident_inventory_with_caller_spelling(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    artifact = GuardArtifact(
        artifact_id="copilot:global:a",
        name="a",
        harness="copilot",
        artifact_type="mcp_server",
        source_scope="global",
        config_path=str(tmp_path / "home" / ".copilot" / "mcp-config.json"),
    )

    def fake_native(kind: str, request: dict[str, object]):
        return (artifact,), (str(tmp_path / "home" / ".copilot" / "mcp-config.json"),), ()

    monkeypatch.setattr(copilot, "native_adapter_detection_with_warnings", fake_native)
    context = HarnessContext(home_dir=Path("home"), workspace_dir=None, guard_home=tmp_path / "guard")

    detection = copilot.CopilotHarnessAdapter().detect(context)

    assert detection.config_paths == (str(Path("home") / ".copilot" / "mcp-config.json"),)
    assert detection.artifacts[0].config_path == str(Path("home") / ".copilot" / "mcp-config.json")
    assert detection.installed is True
    assert detection.warnings == ()
