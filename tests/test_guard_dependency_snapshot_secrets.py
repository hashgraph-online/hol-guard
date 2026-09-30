"""Dependency installation never exempts credential content from snapshots."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.workspace_snapshot_inputs import complete_workspace_snapshot


@pytest.mark.parametrize(
    "relative",
    (
        "node_modules/pkg/clientSecret.json",
        "node_modules/pkg/apiToken.json",
        "node_modules/pkg/serviceAccount.json",
        "node_modules/pkg/privateKey.json",
        "node_modules/pkg/.env",
        "node_modules/@scope/pkg/runtime/clientSecret.json",
        "node_modules/outer/node_modules/inner/apiToken.json",
        "node_modules/clientSecret.json",
    ),
)
def test_dependency_credentials_are_excluded_without_opening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str
) -> None:
    workspace = tmp_path / "workspace"
    protected = workspace / relative
    protected.parent.mkdir(parents=True)
    protected.write_text("synthetic-sensitive-fixture", encoding="utf-8")
    (workspace / "package.json").write_text("{}", encoding="utf-8")
    original_open = os.open

    def guarded_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if isinstance(path, (str, bytes, os.PathLike)) and Path(os.fsdecode(path)) == protected:
            pytest.fail("snapshot opened a dependency credential")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded_open)
    with pytest.raises(ValueError, match="protected workspace content"):
        complete_workspace_snapshot(workspace)
    identity, inputs = complete_workspace_snapshot(workspace, exclude_protected=True)
    assert {item.snapshot_path for item in inputs} == {"package.json"}
    protected.unlink()
    assert complete_workspace_snapshot(workspace, exclude_protected=True)[0] != identity


@pytest.mark.parametrize(
    "relative",
    (
        "node_modules/js-tokens/index.js",
        "node_modules/@secret-scope/js-tokens/index.js",
        "node_modules/outer/node_modules/js-tokens/index.js",
    ),
)
def test_generic_package_names_do_not_exclude_ordinary_code(tmp_path: Path, relative: str) -> None:
    workspace = tmp_path / "workspace"
    source = workspace / relative
    source.parent.mkdir(parents=True)
    source.write_text("export const value = 1;", encoding="utf-8")
    _identity, inputs = complete_workspace_snapshot(workspace, exclude_protected=True)
    assert tuple(item.snapshot_path for item in inputs) == (relative,)
