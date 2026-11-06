from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.managed_install_context import managed_install_context


def _context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "current",
        guard_home=tmp_path / "guard-home",
        executable_overrides={"codex": "/trusted/codex"},
        home_override_explicit=True,
        workspace_override_explicit=True,
    )


def test_managed_install_context_preserves_all_caller_fields(tmp_path: Path) -> None:
    context = _context(tmp_path)
    workspace = tmp_path / "managed"
    workspace.mkdir()

    rebound, persisted_workspace = managed_install_context(context, {"workspace": str(workspace)})

    assert rebound.workspace_dir == workspace.resolve()
    assert persisted_workspace == str(workspace.resolve())
    assert rebound.home_dir == context.home_dir
    assert rebound.guard_home == context.guard_home
    assert rebound.executable_overrides == context.executable_overrides
    assert rebound.home_override_explicit is True
    assert rebound.workspace_override_explicit is True


def test_managed_install_context_clears_only_workspace_when_global(tmp_path: Path) -> None:
    context = _context(tmp_path)

    rebound, persisted_workspace = managed_install_context(context, {"workspace": "  "})

    assert rebound.workspace_dir is None
    assert persisted_workspace is None
    assert rebound.executable_overrides == context.executable_overrides
    assert rebound.workspace_override_explicit is True


def test_managed_install_context_rejects_malformed_workspace_without_partial_rebinding(tmp_path: Path) -> None:
    context = _context(tmp_path)

    with pytest.raises(ValueError, match="managed install workspace path is invalid"):
        managed_install_context(context, {"workspace": "invalid\x00path"})
