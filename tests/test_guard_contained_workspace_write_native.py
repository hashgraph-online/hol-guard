"""The workspace-write wrapper hands execution to the resident and never decides in Python."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import contained_workspace_write_execution

_SENTINEL = object()


def _dirs(tmp_path: Path) -> tuple[Path, Path]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    return workspace, guard_home


def test_workspace_write_unavailable_workspace_or_resident_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, guard_home = _dirs(tmp_path)
    monkeypatch.setattr(
        contained_workspace_write_execution._native_execution,
        "contained_workspace_write_execute_native",
        lambda *a, **k: None,
    )
    assert (
        contained_workspace_write_execution.try_execute_contained_workspace_write(
            "copy-generated", workspace=workspace, guard_home=guard_home, source="a.txt", target="b.txt"
        )
        is None
    )
    assert (
        contained_workspace_write_execution.try_execute_contained_workspace_write(
            "copy-generated",
            workspace=tmp_path / "missing",
            guard_home=guard_home,
            source="a.txt",
            target="b.txt",
        )
        is None
    )


def test_workspace_write_passes_canonical_workspace_and_scrubbed_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, guard_home = _dirs(tmp_path)
    seen: dict[str, Any] = {}

    def native(canonical: Path, **kwargs: Any) -> object:
        seen["workspace"] = canonical
        seen.update(kwargs)
        return _SENTINEL

    monkeypatch.setattr(
        contained_workspace_write_execution._native_execution, "contained_workspace_write_execute_native", native
    )
    result = contained_workspace_write_execution.try_execute_contained_workspace_write(
        "format-write",
        workspace=workspace,
        guard_home=guard_home,
        source="m.py",
        target="m.py",
        environment={"PATH": "/usr/bin", "GITHUB_TOKEN": "synthetic-secret"},
    )
    assert result is _SENTINEL
    assert seen["workspace"] == workspace.resolve()
    assert seen["operation"] == "format-write"
    assert "GITHUB_TOKEN" not in seen["environment"]
    assert seen["environment"]["PATH"] == "/usr/bin"


def test_workspace_write_tool_search_path_reaches_the_resident_without_other_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, guard_home = _dirs(tmp_path)
    seen: dict[str, Any] = {}
    monkeypatch.setattr(
        contained_workspace_write_execution._native_execution,
        "contained_workspace_write_execute_native",
        lambda canonical, **kwargs: seen.update(kwargs),
    )
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-secret")
    monkeypatch.setenv("LANG", "C")
    for name in ("LC_ALL", "LC_CTYPE", "NO_COLOR", "TERM"):
        monkeypatch.delenv(name, raising=False)
    contained_workspace_write_execution.try_execute_contained_workspace_write(
        "patch-check", workspace=workspace, guard_home=guard_home, source="p.diff"
    )
    assert seen["environment"] == {"LANG": "C", "PATH": "/usr/local/bin:/usr/bin"}


@pytest.mark.parametrize(("requested", "sent"), [(0.25, 1), (1.0, 1), (1.2, 2), (120.0, 120)])
def test_workspace_write_timeout_is_rounded_up_never_to_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, requested: float, sent: int
) -> None:
    from codex_plugin_scanner.guard import native_execution

    workspace, guard_home = _dirs(tmp_path)
    captured: dict[str, Any] = {}

    def resident(**kwargs: Any) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(native_execution, "_resident_request", resident)
    assert (
        native_execution.contained_workspace_write_execute_native(
            workspace,
            guard_home=guard_home,
            operation="patch-check",
            source="p.diff",
            timeout_seconds=requested,
        )
        is None
    )
    assert captured["request"]["timeout_seconds"] == sent


@pytest.mark.parametrize("requested", [0.0, -1.0, float("nan"), float("inf")])
def test_workspace_write_invalid_timeout_never_reaches_the_resident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, requested: float
) -> None:
    from codex_plugin_scanner.guard import native_execution

    workspace, guard_home = _dirs(tmp_path)
    called: list[object] = []
    monkeypatch.setattr(native_execution, "_resident_request", lambda **kwargs: called.append(kwargs))
    assert (
        native_execution.contained_workspace_write_execute_native(
            workspace, guard_home=guard_home, operation="patch-check", source="p.diff", timeout_seconds=requested
        )
        is None
    )
    assert called == []
