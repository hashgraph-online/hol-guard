"""The plugin's ``node --check`` must not execute inherited preloads or the plugin."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.native_harness import ask


def _context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HarnessContext:
    monkeypatch.delenv("CLINE_DIR", raising=False)
    monkeypatch.delenv("CLINE_DATA_DIR", raising=False)
    home = tmp_path / "home with spaces"
    home.mkdir()
    return HarnessContext(home, None, home / ".hol-guard")


def _install(context: HarnessContext) -> dict[str, Any]:
    facts = {"guard_cli": ["guard"], "hook_argv": None, "identity": None}
    return ask("install_transport", context, harness="cline", transport="plugin", frozen=False, facts=facts)


@pytest.mark.parametrize("custom", [False, True])
def test_install_checks_the_managed_index_with_node(tmp_path, monkeypatch, custom) -> None:
    context = _context(tmp_path, monkeypatch)
    if custom:
        monkeypatch.setenv("CLINE_DATA_DIR", str(context.home_dir / "custom-cline"))
    answer = _install(context)
    index = answer["manifest"]["managed_plugin_path"]
    verdict = answer["probe"]["result"]
    if shutil.which("node") is None:
        assert verdict == {"ok": True, "skipped": True, "reason": "node_not_available"}
    else:
        assert verdict == {"ok": True, "return_code": 0}
    expected = context.home_dir / ("custom-cline" if custom else ".cline") / "plugins" / "hol-guard" / "index.js"
    assert Path(index) == expected
