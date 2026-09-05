"""Saved plugin state must not control Node options or probe arbitrary paths."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.adapters import cline_plugin, cline_plugin_probe
from codex_plugin_scanner.guard.adapters.base import HarnessContext


def _context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HarnessContext:
    monkeypatch.delenv("CLINE_DIR", raising=False)
    monkeypatch.delenv("CLINE_DATA_DIR", raising=False)
    home = tmp_path / "home with spaces"
    home.mkdir()
    return HarnessContext(home, None, home / ".hol-guard")


def _write_state(context: HarnessContext, value: object) -> None:
    state = cline_plugin._state_path(context)
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps({"index_path": value}), encoding="utf-8")


@pytest.mark.parametrize("value", ["--require=untrusted.js", "--eval=process.exit(0)", "../index.js", None, 7])
def test_bad_recorded_plugin_path_never_starts_node(tmp_path, monkeypatch, value) -> None:
    context = _context(tmp_path, monkeypatch)
    _write_state(context, value)
    run = Mock(side_effect=AssertionError("must not start Node"))
    monkeypatch.setattr(cline_plugin_probe.shutil, "which", Mock(return_value="node"))
    monkeypatch.setattr(cline_plugin_probe.subprocess, "run", run)

    result = cline_plugin.cline_plugin_syntax_probe(context)

    assert result["ok"] is False
    run.assert_not_called()


def test_external_regular_file_is_not_a_plugin_probe_target(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path, monkeypatch)
    external = tmp_path / "external.js"
    external.write_text("export default {};", encoding="utf-8")
    _write_state(context, str(external))
    run = Mock(side_effect=AssertionError("must not start Node"))
    monkeypatch.setattr(cline_plugin_probe.subprocess, "run", run)

    assert cline_plugin.cline_plugin_syntax_probe(context) == {"ok": False, "reason": "plugin_state_path_mismatch"}
    run.assert_not_called()


def test_managed_probe_ends_option_parsing_and_preserves_exit_status(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path, monkeypatch)
    path = cline_plugin.cline_plugin_root(context) / "index.js"
    _write_state(context, str(path))
    run = Mock(return_value=subprocess.CompletedProcess([], 1))
    monkeypatch.setattr(cline_plugin_probe.shutil, "which", Mock(return_value="node"))
    monkeypatch.setattr(cline_plugin_probe.subprocess, "run", run)

    assert cline_plugin.cline_plugin_syntax_probe(context) == {"ok": False, "return_code": 1}
    run.assert_called_once_with(
        ["node", "--check", "--", str(path)], capture_output=True, text=True, timeout=5, check=False
    )


def test_unsafe_managed_root_never_starts_node(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path, monkeypatch)
    _write_state(context, "index.js")
    run = Mock(side_effect=AssertionError("must not start Node"))
    monkeypatch.setattr(cline_plugin_probe.subprocess, "run", run)
    monkeypatch.setattr(cline_plugin_probe, "cline_plugin_root", Mock(side_effect=RuntimeError("symlink")))

    assert cline_plugin.cline_plugin_syntax_probe(context) == {"ok": False, "reason": "plugin_path_unsafe"}
    run.assert_not_called()


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is not installed")
@pytest.mark.parametrize("source,ok", [("module.exports = {};", True), ("function broken( {", False)])
def test_real_node_checks_managed_source_without_executing_it(tmp_path, monkeypatch, source, ok) -> None:
    context = _context(tmp_path, monkeypatch)
    path = cline_plugin.cline_plugin_root(context) / "index.js"
    path.parent.mkdir(parents=True)
    marker = tmp_path / "must-not-run"
    prelude = f"require('node:fs').writeFileSync({json.dumps(str(marker))}, 'executed');\n"
    path.write_text(prelude + source, encoding="utf-8")
    _write_state(context, str(path))

    assert cline_plugin.cline_plugin_syntax_probe(context)["ok"] is ok
    assert not marker.exists()
