"""The request the Claude Code detection facade sends the native resident."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import aibom_detection
from codex_plugin_scanner.guard.adapters import claude_code
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.models import HarnessDetection

VECTORS = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/testdata/claude_code/vectors.json"
CASES = json.loads(VECTORS.read_text(encoding="utf-8"))["cases"]


def _scrub(value: object, root: Path) -> object:
    return json.loads(json.dumps(value, ensure_ascii=False).replace(str(root), "<ROOT>"))


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_detect_sends_the_recorded_request(case: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[tuple[str, dict[str, object]]] = []

    def fake_native(kind: str, request: dict[str, object]):
        sent.append((kind, request))
        return (), ("/seen",), ()

    monkeypatch.setattr(claude_code, "native_adapter_detection_with_warnings", fake_native)
    monkeypatch.setattr(
        aibom_detection, "extend_detection_with_workspace_aibom", lambda detection, **_kwargs: detection
    )
    root = tmp_path.resolve()
    base = Path() if case["relative"] else root
    if case["relative"]:
        monkeypatch.chdir(root)
    context = HarnessContext(
        home_dir=base / case["home"],
        workspace_dir=None if case["workspace"] is None else base / case["workspace"],
        guard_home=root / "guard-home",
    )

    detection = claude_code.ClaudeCodeHarnessAdapter().detect(context)

    assert isinstance(detection, HarnessDetection)
    assert detection.installed is True
    assert detection.config_paths == ("/seen",)
    kind, request = sent[0]
    assert kind == "claude_code_detect"
    assert _scrub(request, root) == case["args"]
