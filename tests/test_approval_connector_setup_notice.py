"""Commands waiting on one connector raise a setup notice, not an approval notice."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import approvals


class _Store:
    guard_home = Path("/nonexistent-guard-home")

    def __init__(self, notified: dict[str, str]) -> None:
        self.notified = notified

    def approval_desktop_notified_at(self, request_id: str) -> str | None:
        return self.notified.get(request_id)

    def mark_approval_desktop_notified(self, request_id: str, notified_at: str) -> None:
        self.notified[request_id] = notified_at


def _notice(request_id: str, group: str | None) -> approvals._QueuedNotice:
    return approvals._QueuedNotice(
        request_id=request_id,
        harness="codex",
        workspace=None,
        approval_url=f"http://127.0.0.1:4781/approvals/{request_id}",
        artifact_name="Bash",
        risk_headline="lanectl status",
        trigger_summary=None,
        queue_group_id=group,
    )


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    delivered: list[object] = []

    def _deliver(notification: object, *, on_success: object) -> bool:
        delivered.append(notification)
        on_success()  # type: ignore[operator]
        return True

    monkeypatch.setattr(approvals, "load_guard_config", lambda *_args: None)
    monkeypatch.setattr(approvals, "load_guard_daemon_auth_token", lambda _home: None)
    monkeypatch.setattr(approvals, "notify_pending_approval_once", _deliver)
    return delivered


def test_a_connector_command_raises_a_setup_notice(sent: list[object]) -> None:
    approvals._notify_pending_approval(store=_Store({}), request=_notice("c-1", "connector:aa11:0000000000000001"))  # type: ignore[arg-type]

    assert [note.title for note in sent] == ["HOL Guard: a connector needs setup"]  # type: ignore[attr-defined]
    assert "connector Guard has not set up yet: lanectl status" in sent[0].message  # type: ignore[attr-defined]


def test_another_request_keeps_the_approval_notice(sent: list[object]) -> None:
    approvals._notify_pending_approval(store=_Store({}), request=_notice("r-1", "qg-1"))  # type: ignore[arg-type]

    assert [note.title for note in sent] == ["HOL Guard needs approval"]  # type: ignore[attr-defined]


def test_a_sibling_the_store_reports_as_notified_stays_silent(sent: list[object]) -> None:
    # The store answers a connector request with the marker of the group's
    # first notified request, so the second command raises nothing.
    store = _Store({"c-2": "2026-03-01T12:00:00+00:00"})

    approvals._notify_pending_approval(store=store, request=_notice("c-2", "connector:aa11:0000000000000002"))  # type: ignore[arg-type]

    assert sent == []
