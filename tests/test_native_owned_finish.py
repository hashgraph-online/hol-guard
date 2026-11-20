"""Ending an installation owner releases its leases even when the resident forgot the owner."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_owned


def _owner() -> native_owned.CodexInstallOwner:
    return native_owned.CodexInstallOwner(Path("/g"), "op", "target", "actor", 1, 2, "token")


@pytest.mark.parametrize(
    ("answer", "released"),
    [({"ok": True, "ended": True}, False), ({"ok": True, "ended": False}, True), ({"ok": True}, True)],
)
def test_an_owner_the_resident_forgot_gets_its_leases_released(
    monkeypatch: pytest.MonkeyPatch, answer: dict[str, object], released: bool
) -> None:
    released_leases: list[str] = []
    monkeypatch.setattr(native_owned, "_call", lambda *_args, **_kwargs: answer)
    monkeypatch.setattr(native_owned, "_release", lambda leases: released_leases.extend(leases))
    native_owned._finish(_owner(), ["a", "b"], committed=True)
    assert released_leases == (["a", "b"] if released else [])


def test_a_failed_end_call_still_releases_the_leases(monkeypatch: pytest.MonkeyPatch) -> None:
    released_leases: list[str] = []

    def failing(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise RuntimeError("down")

    monkeypatch.setattr(native_owned, "_call", failing)
    monkeypatch.setattr(native_owned, "_release", lambda leases: released_leases.extend(leases))
    native_owned._finish(_owner(), ["a"], committed=False)
    assert released_leases == ["a"]
