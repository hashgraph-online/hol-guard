"""Tests for attested OpenCode hook-interpreter resolution."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.hook_python import (
    _guard_hook_python_candidates,
    attest_guard_hook_python,
    filter_worktree_path_entries,
    resolve_guard_hook_python,
)
from codex_plugin_scanner.guard.adapters.opencode_pretool import pretool_plugin_source


def _ctx(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )


def test_filter_worktree_path_entries_drops_worktree_paths() -> None:
    worktree_src = "/Users/me/CascadeProjects/hol-guard-wt-opencode-trusted-hook/src"
    stable = "/Users/me/.local/pipx/venvs/hol-guard/lib/python3.12/site-packages"
    filtered = filter_worktree_path_entries(
        [
            worktree_src,
            "/repo/.worktrees/feature/src",
            "/repo/worktrees/feature/src",
            stable,
        ]
    )
    assert filtered == [stable]


def test_guard_hook_python_candidates_skip_worktree_venv(tmp_path: Path) -> None:
    workspace = tmp_path / "hol-guard-wt-dev"
    workspace.mkdir()
    venv_python = workspace / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_text("", encoding="utf-8")
    ctx = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
        guard_home=tmp_path / "guard-home",
    )
    candidates = _guard_hook_python_candidates(ctx)
    assert venv_python.resolve() not in candidates


def test_pretool_plugin_source_uses_parent_attested_import_roots(tmp_path: Path) -> None:
    context = _ctx(tmp_path)
    attestation = attest_guard_hook_python(context)

    source = pretool_plugin_source(context)

    assert str(attestation.package_root) in source
    assert str(attestation.cryptography_distribution_root) in source
    assert str(attestation.identity.target_path) in source
    assert attestation.identity.target_sha256 in source


def test_resolve_guard_hook_python_finds_current_interpreter(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    python = resolve_guard_hook_python(ctx)
    assert python.is_file()
    assert "hol-guard-wt" not in str(python)
