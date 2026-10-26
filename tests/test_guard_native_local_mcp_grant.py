"""Caller-side inputs for the resident's MCP grant decision."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_mcp_extension_input import _caller_launcher_path, build_extension_input
from codex_plugin_scanner.guard.store import GuardStore

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401
from .test_guard_local_mcp_grants import _artifact, _identity


def test_relative_path_entries_are_anchored_to_the_callers_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    absolute = str(tmp_path / "abs")
    joined = os.pathsep.join(["node_modules/.bin", absolute, ""])

    anchored = _caller_launcher_path(joined)

    assert anchored == os.pathsep.join([os.path.join(os.getcwd(), "node_modules/.bin"), absolute, ""])
    assert _caller_launcher_path(None) is None


def test_unreadable_working_directory_is_held_only_when_a_relative_entry_needs_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def deleted_cwd() -> str:
        raise FileNotFoundError("cwd removed")

    monkeypatch.setattr(os, "getcwd", deleted_cwd)
    absolute = str(tmp_path / "abs")
    store = GuardStore(tmp_path / "guard-home")
    artifact = _artifact(_identity(), "read_file")

    monkeypatch.setenv("PATH", absolute)
    assert build_extension_input(store, artifact)["local_unavailable"] is False
    monkeypatch.setenv("PATH", os.pathsep.join(["node_modules/.bin", absolute]))
    held = build_extension_input(store, artifact)
    assert held["local_unavailable"] is True
    assert held["launcher_path"] is None


def test_unpinned_store_sends_no_store_path_so_the_resident_holds_the_call(tmp_path: Path) -> None:
    artifact = _artifact(_identity(), "read_file")
    ext = build_extension_input(object(), artifact)
    assert (ext["store_path"], ext["guard_home"], ext["layers"]) == ("", "", [])


def test_unreadable_control_layers_are_flagged_instead_of_raising(tmp_path: Path) -> None:
    class _BrokenStore:
        path = tmp_path / "guard-home" / "guard.db"
        guard_home = tmp_path / "guard-home"

        def read_extension_control_authority_for_registry(self, _registry: object, **_kwargs) -> object:
            raise RuntimeError("control authority requires a native mutation")

    ext = build_extension_input(_BrokenStore(), _artifact(_identity(), "read_file"))
    assert (ext["layers"], ext["layers_unavailable"]) == ([], True)
    assert build_extension_input(object(), _artifact(_identity(), "read_file"))["layers_unavailable"] is False
