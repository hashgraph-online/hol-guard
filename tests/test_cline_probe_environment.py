"""Cline syntax probes must not execute inherited preloads or follow untrusted paths."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.adapters import cline_plugin, cline_plugin_probe
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline_paths import cline_plugin_root, ensure_safe_cline_destination


@pytest.fixture
def context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HarnessContext:
    monkeypatch.delenv("CLINE_DATA_DIR", raising=False)
    monkeypatch.delenv("CLINE_DIR", raising=False)
    home = tmp_path / "home"
    home.mkdir()
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard")


@pytest.mark.parametrize("custom", [False, True])
def test_cline_node_check_uses_canonical_operand_and_isolated_environment(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch, custom: bool
) -> None:
    if custom:
        monkeypatch.setenv("CLINE_DATA_DIR", str(context.home_dir / "custom-cline"))
    script = cline_plugin_root(context) / "index.js"
    monkeypatch.setenv("NODE_OPTIONS", "--require=untrusted.js")
    monkeypatch.setenv("NODE_PATH", "/untrusted/modules")
    monkeypatch.setenv("LD_PRELOAD", "/untrusted/library.so")
    monkeypatch.setattr(cline_plugin_probe.shutil, "which", Mock(return_value="/trusted/node"))
    run = Mock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(cline_plugin_probe.subprocess, "run", run)

    monkeypatch.setattr(cline_plugin, "_load_state", Mock(return_value={"index_path": str(script)}))
    assert cline_plugin.cline_plugin_syntax_probe(context) == {"ok": True, "return_code": 0}
    run.assert_called_once()
    assert run.call_args.args[0] == ["/trusted/node", "--check", "--", str(script)]
    assert run.call_args.kwargs["check"] is False
    assert run.call_args.kwargs["timeout"] == 5
    for name in ("NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD"):
        assert name not in run.call_args.kwargs["env"]


@pytest.mark.parametrize("dangling", [False, True])
@pytest.mark.parametrize("ancestor", [False, True])
def test_cline_rejects_existing_and_dangling_symlink_paths(
    context: HarnessContext, dangling: bool, ancestor: bool
) -> None:
    target = context.home_dir / "target"
    if not dangling:
        target.mkdir()
    link = context.home_dir / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(RuntimeError, match="symlink"):
        ensure_safe_cline_destination(context, link / "index.js" if ancestor else link)


def test_cline_outside_path_is_rejected_before_resolving_it(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = context.home_dir.parent / "outside" / "index.js"
    original = Path.resolve
    calls: list[Path] = []

    def resolve(path: Path, *args, **kwargs):
        calls.append(path)
        if path == outside.parent:
            raise AssertionError("outside path must be rejected lexically")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)
    with pytest.raises(RuntimeError, match="escapes"):
        ensure_safe_cline_destination(context, outside)
    assert outside.parent not in calls


@pytest.mark.parametrize("path_kind", ["home", "guard", "configured", "traversal", "prefix", "parent_target"])
def test_cline_destination_containment(context: HarnessContext, monkeypatch: pytest.MonkeyPatch, path_kind: str) -> None:
    paths = {
        "home": context.home_dir / "Documents/Cline/Hooks/PreToolUse",
        "guard": context.guard_home / "managed/cline/hook.py",
        "configured": context.home_dir / "custom/plugins/hol-guard/index.js",
        "traversal": context.home_dir / "../outside/index.js",
        "parent_target": context.home_dir / "..",
        "prefix": context.home_dir.parent / (context.home_dir.name + "-other") / "index.js",
    }
    monkeypatch.setenv("CLINE_DATA_DIR", str(context.home_dir / "custom"))
    if path_kind in {"traversal", "prefix", "parent_target"}:
        with pytest.raises(RuntimeError, match="escapes"):
            ensure_safe_cline_destination(context, paths[path_kind])
    else:
        ensure_safe_cline_destination(context, paths[path_kind])


def test_canonical_configured_path_accepts_physical_home_alias(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    alias = context.home_dir.parent / "home-alias"
    try:
        alias.symlink_to(context.home_dir, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    aliased = HarnessContext(home_dir=alias, workspace_dir=None, guard_home=context.guard_home)
    monkeypatch.setenv("CLINE_DATA_DIR", str(context.home_dir / "custom"))
    ensure_safe_cline_destination(aliased, context.home_dir / "custom/plugins/hol-guard/index.js")
