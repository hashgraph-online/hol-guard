"""The request the Pi and Oh My Pi detection facade sends the native resident."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import pi
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.models import HarnessDetection

VECTORS = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/testdata/pi/vectors.json"
CASES = json.loads(VECTORS.read_text(encoding="utf-8"))["cases"]


def _scrub(value: object, root: Path) -> object:
    return json.loads(json.dumps(value, ensure_ascii=False).replace(str(root), "<ROOT>"))


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_detect_sends_the_recorded_request(case: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[tuple[str, dict[str, object]]] = []

    def fake_native(kind: str, request: dict[str, object]):
        sent.append((kind, request))
        return (), ("/seen",), ()

    monkeypatch.setattr(pi, "native_adapter_detection_with_warnings", fake_native)
    monkeypatch.setattr(pi, "extend_detection_with_workspace_aibom", lambda detection, **_kwargs: detection)
    root = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(root / case["home"]))
    base = Path() if case["relative"] else root
    if case["relative"]:
        monkeypatch.chdir(root)
    home_dir = base / case["home"]
    workspace = home_dir if case["workspace_is_home"] else base / "work"
    context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=None if case["no_workspace"] else workspace,
        guard_home=root / "guard-home",
    )
    adapter = pi.OmpHarnessAdapter() if case["harness"] == "omp" else pi.PiHarnessAdapter()

    detection = adapter.detect(context)

    assert isinstance(detection, HarnessDetection)
    assert detection.installed is True
    assert detection.config_paths == ("/seen",)
    kind, request = sent[0]
    assert kind == "pi_detect"
    assert _scrub(request, root) == case["args"]
