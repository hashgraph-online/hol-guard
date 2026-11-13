"""The plugin's ``node --check`` must not execute inherited preloads or the plugin."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.adapters import cline_runtime
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.native_harness import ask
from tests.coverage_ci import under_coverage_scale


def _context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HarnessContext:
    monkeypatch.delenv("CLINE_DIR", raising=False)
    monkeypatch.delenv("CLINE_DATA_DIR", raising=False)
    home = tmp_path / "home with spaces"
    home.mkdir()
    return HarnessContext(home, None, home / ".hol-guard")


def _install(context: HarnessContext) -> dict[str, object]:
    facts = {"guard_cli": ["guard"], "hook_argv": None, "identity": None}
    return ask("install_transport", context, harness="cline", transport="plugin", frozen=False, facts=facts)


@pytest.mark.parametrize("custom", [False, True])
def test_install_asks_node_to_check_the_managed_index(tmp_path, monkeypatch, custom) -> None:
    context = _context(tmp_path, monkeypatch)
    if custom:
        monkeypatch.setenv("CLINE_DATA_DIR", str(context.home_dir / "custom-cline"))
    answer = _install(context)
    index = answer["manifest"]["managed_plugin_path"]
    assert answer["probe"] == {"node_check": index}
    expected = context.home_dir / ("custom-cline" if custom else ".cline") / "plugins" / "hol-guard" / "index.js"
    assert Path(index) == expected


def test_node_check_ends_option_parsing_and_drops_inherited_preloads(monkeypatch) -> None:
    monkeypatch.setenv("NODE_OPTIONS", "--require=untrusted.js")
    monkeypatch.setenv("NODE_PATH", "/untrusted/modules")
    monkeypatch.setenv("LD_PRELOAD", "/untrusted/library.so")
    monkeypatch.setattr(cline_runtime.shutil, "which", Mock(return_value="/trusted/node"))
    run = Mock(return_value=subprocess.CompletedProcess([], 1))
    monkeypatch.setattr(cline_runtime.subprocess, "run", run)

    assert cline_runtime._node_check("--eval=index.js") == {"ok": False, "return_code": 1}  # pyright: ignore[reportPrivateUsage]
    run.assert_called_once()
    assert run.call_args.args[0] == ["/trusted/node", "--check", "--", "--eval=index.js"]
    assert run.call_args.kwargs["check"] is False
    assert run.call_args.kwargs["timeout"] == 5
    for name in ("NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD"):
        assert name not in run.call_args.kwargs["env"]


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is not installed")
@pytest.mark.parametrize("source,ok", [("export default {};", True), ("function broken( {", False)])
def test_real_node_checks_managed_source_without_executing_it(tmp_path, monkeypatch, source, ok) -> None:
    context = _context(tmp_path, monkeypatch)
    index = Path(_install(context)["manifest"]["managed_plugin_path"])
    marker = tmp_path / "must-not-run"
    prelude = f"require('node:fs').writeFileSync({json.dumps(str(marker))}, 'executed');\n"
    index.write_text(prelude + source, encoding="utf-8")

    original_run = subprocess.run

    def traced_run(*args, **kwargs):
        # Keep the production probe's 5s contract pinned by the mock test above,
        # but give a real Node process room to start on a saturated CI host.
        kwargs["timeout"] = max(kwargs["timeout"] * under_coverage_scale(3.0), 15)
        return original_run(*args, **kwargs)

    monkeypatch.setattr(cline_runtime.subprocess, "run", traced_run)
    result = cline_runtime._node_check(str(index))  # pyright: ignore[reportPrivateUsage]
    assert result["ok"] is ok, result
    assert not marker.exists()
