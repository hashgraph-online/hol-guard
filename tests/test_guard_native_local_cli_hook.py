"""The hook-time local CLI client presents only a bound, in-range resident answer."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import local_cli_hook as client


def _reply(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status: str = "ok",
    code: str = "ok",
    payload: object = None,
    bind: bool = True,
    prerequisite: bool = True,
) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []

    def resident(**kwargs: object) -> dict[str, object]:
        request = kwargs["request"]
        assert isinstance(request, dict)
        calls.append(kwargs)
        digest = "sha256:" + client._canonical_request_sha256(request)
        return {
            "schema": "guard-local-cli-hook-result.v1",
            "request_id": request["request_id"],
            "request_sha256": digest if bind else "sha256:" + "0" * 64,
            "status": status,
            "code": code,
            "payload": payload,
        }

    monkeypatch.setattr(client, "_resident_request", resident)
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _home: prerequisite)
    return calls


def _ask(
    tmp_path: Path, action: str = "review", *, grant_allowed: bool = True, recovered: list[object] | None = None
) -> object:
    store = SimpleNamespace(
        path=tmp_path / "guard.db",
        guard_home=tmp_path,
        guard_source="local",
        _repair_store_permissions=lambda: None,
        _recover_fatal_sqlite_store=(recovered if recovered is not None else []).append,
    )
    return client.native_local_cli_hook(
        store,
        command="pnpm run build",
        cwd=tmp_path,
        home_dir=None,
        current_action=action,
        grant_allowed=grant_allowed,
    )


def test_presents_the_resident_action(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _reply(monkeypatch, payload={"action": "allow"})

    assert _ask(tmp_path, grant_allowed=False) == "allow"
    request = calls[0]["request"]
    assert calls[0]["operation"] == "local_cli_hook"
    assert isinstance(request, dict)
    assert request["grant_allowed"] is False
    assert request["home_dir"] is None
    assert request["store_path"] == str(tmp_path / "guard.db")
    assert request["source"] == "local"


@pytest.mark.parametrize(
    "reply",
    [
        {"payload": {"action": "allow"}, "bind": False},
        {"payload": {"action": "allow"}, "prerequisite": False},
        {"payload": {"action": "warn"}},
        {"payload": {"action": "allow", "extra": True}},
        {"payload": {"action": ["allow"]}},
        {"status": "error", "code": "native_local_cli_hook_path_invalid"},
    ],
)
def test_no_bound_answer_is_none(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reply: dict[str, object]) -> None:
    _reply(monkeypatch, **reply)

    assert _ask(tmp_path) is None


def test_store_failure_recovers_and_raises_like_the_store_call(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _reply(monkeypatch, status="error", code="native_guard_store_sqlite_corrupt")
    recovered: list[object] = []

    with pytest.raises(sqlite3.DatabaseError) as raised:
        _ask(tmp_path, recovered=recovered)

    assert recovered == [raised.value]
    assert getattr(raised.value, "sqlite_errorcode", None) == 11


def test_spent_operation_deadline_raises_before_the_call(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _reply(monkeypatch, payload={"action": "allow"})
    monkeypatch.setattr(client, "sqlite_operation_deadline_monotonic", lambda: 0.0)

    with pytest.raises(TimeoutError):
        _ask(tmp_path)
    assert calls == []


def test_large_environment_fits_the_request(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _reply(monkeypatch, payload={"action": "allow"})

    _ask(tmp_path)

    assert calls[0]["max_request_bytes"] == 2 * 1024 * 1024
