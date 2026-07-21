# pyright: reportUnknownArgumentType=false, reportUnknownLambdaType=false

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.github_workflow_context import (
    GitHubWorkflowDescriptor,
    build_github_workflow_descriptor,
)

_COMMAND = f"{Path(sys.executable).resolve()} issue lock 17 --repo example/repo"
_OVERSIZED_FILE_BYTES = 8 * 1024 * 1024 + 1


def _stub_github_context(monkeypatch: pytest.MonkeyPatch) -> None:
    import codex_plugin_scanner.guard.runtime.github_workflow_context as context_module

    monkeypatch.setattr(context_module, "_resolve_executable", lambda _name, _env: Path(sys.executable).resolve())
    monkeypatch.setattr(
        context_module,
        "_run_bounded",
        lambda arguments, **_kwargs: (
            b"https://github.com/example/repo.git\n" if "remote.origin.url" in arguments else b'{"login":"reviewer"}'
        ),
    )


def _build_descriptor(workspace: Path) -> GitHubWorkflowDescriptor | None:
    return build_github_workflow_descriptor(
        _COMMAND,
        workspace=workspace,
        config_path=str(workspace / "config.toml"),
        configuration={"mode": "enforce"},
        sandbox={"analysis": True},
        environment={"PATH": os.environ.get("PATH", "")},
    )


@pytest.mark.parametrize("name", ("pyproject.toml", "package.json", "uv.lock", "bun.lock", "bun.lockb"))
def test_oversized_named_binding_file_fails_closed_at_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    _stub_github_context(monkeypatch)
    with (tmp_path / name).open("wb") as stream:
        _ = stream.truncate(_OVERSIZED_FILE_BYTES)

    assert _build_descriptor(tmp_path) is None


@pytest.mark.parametrize("kind", ("directory", "symlink"))
def test_non_regular_named_binding_file_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    _stub_github_context(monkeypatch)
    manifest = tmp_path / "package.json"
    if kind == "directory":
        manifest.mkdir()
    else:
        target = tmp_path / "actual-package.json"
        _ = target.write_text("{}", encoding="utf-8")
        try:
            manifest.symlink_to(target)
        except OSError:
            pytest.skip("symlink creation is unavailable")

    assert _build_descriptor(tmp_path) is None


def test_unreadable_named_binding_file_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_github_context(monkeypatch)
    manifest = tmp_path / "package.json"
    _ = manifest.write_text("{}", encoding="utf-8")
    original_open = Path.open

    def open_with_denial(
        path: Path,
        mode: str = "r",
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ):
        if path == manifest:
            raise PermissionError("manifest read denied")
        return original_open(path, mode, buffering, encoding, errors, newline)

    monkeypatch.setattr(Path, "open", open_with_denial)
    assert _build_descriptor(tmp_path) is None


def test_oversized_binding_file_cannot_retain_empty_digest_at_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_github_context(monkeypatch)
    approved = _build_descriptor(tmp_path)
    assert approved is not None

    with (tmp_path / "package.json").open("wb") as stream:
        _ = stream.truncate(_OVERSIZED_FILE_BYTES)

    assert _build_descriptor(tmp_path) is None
