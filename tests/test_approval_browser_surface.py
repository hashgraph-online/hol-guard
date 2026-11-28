"""R-SURFACE: a live browser session the agent drives keeps automatic approval pages closed."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import approval_browser_surface, native_runner_authority
from codex_plugin_scanner.guard.runtime import surface_server
from codex_plugin_scanner.guard.runtime.surface_server import GuardSurfaceRuntime
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize(
    ("answer", "held"),
    [
        ({"approval_page_held": True}, True),
        ({"approval_page_held": False}, False),
        ({"approval_page_held": "yes"}, False),
        ({}, False),
    ],
)
def test_the_native_answer_decides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: dict[str, object], held: bool
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def fake(kind: str, args: dict[str, object], *_args: object, **_kwargs: object) -> dict[str, object]:
        calls.append((kind, dict(args)))
        return answer

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", fake)
    assert approval_browser_surface.approval_page_held(tmp_path) is held
    assert calls == [("approval_browser_surface", {"guard_home": str(tmp_path)})]


def test_a_runtime_that_cannot_answer_holds_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise RuntimeError("native_runner_authority_resident_unavailable")

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", fail)
    assert approval_browser_surface.approval_page_held(tmp_path) is False


def _ensure(runtime: GuardSurfaceRuntime, opened: list[str], *, force_open: bool = False) -> dict[str, object]:
    return runtime.ensure_surface(
        surface="approval-center",
        approval_center_url="http://127.0.0.1:5474",
        approval_surface_policy="auto-open-once",
        open_key="approval-request:request-1",
        force_open=force_open,
        opener=lambda url: opened.append(url) or True,
    )


def test_a_held_page_is_not_opened_automatically(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(surface_server, "approval_page_held", lambda _home: True)
    runtime = GuardSurfaceRuntime(GuardStore(tmp_path / "guard-home"))
    opened: list[str] = []

    result = _ensure(runtime, opened)

    assert result["opened"] is False
    assert result["reason"] == "browser-session-held"
    assert opened == []


def test_an_explicit_open_still_opens_a_held_page(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(surface_server, "approval_page_held", lambda _home: True)
    runtime = GuardSurfaceRuntime(GuardStore(tmp_path / "guard-home"))
    opened: list[str] = []

    result = _ensure(runtime, opened, force_open=True)

    assert result["opened"] is True
    assert opened == ["http://127.0.0.1:5474"]


def test_without_a_held_page_the_policy_opens_as_before(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(surface_server, "approval_page_held", lambda _home: False)
    runtime = GuardSurfaceRuntime(GuardStore(tmp_path / "guard-home"))
    opened: list[str] = []

    assert _ensure(runtime, opened)["opened"] is True
    assert opened == ["http://127.0.0.1:5474"]
