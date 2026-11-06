"""Commands waiting on one connector raise a setup notice, not an approval notice."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import approvals
from codex_plugin_scanner.guard.daemon import hook_native_review_approval as review


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


_GROUP = "connector:" + "a" * 64 + ":0123456789abcdef"


class _QueueStore(_Store):
    """A store whose notified marker answers with the group's first notified sibling, as the real one does.

    Its queue call finds ``connector`` for a review that sends a lookup, as
    the resident does, and answers it as ``connector_setup``.
    """

    def __init__(self, connector: str | None = "lanectl") -> None:
        super().__init__({})
        self.rows: dict[str, dict[str, object]] = {}
        self.connector = connector

    def add_approval_request(self, request: object, _now: str) -> str:
        row = {key: getattr(request, key) for key in ("request_id", "harness", "approval_url", "workspace")}
        row["queue_group_id"] = request.queue_group_id  # type: ignore[attr-defined]
        self.rows[str(row["request_id"])] = row
        return str(row["request_id"])

    def get_approval_request(self, request_id: str) -> dict[str, object]:
        return self.rows[request_id]

    def queue_native_review(self, review: dict[str, object], now: str, **options: object) -> dict[str, object]:
        found = self.connector if options.get("connector_lookup") is not None else None
        if found is not None:
            review = {**review, "queue_group_id": _GROUP}
        row = self.get_approval_request(self.add_approval_request(SimpleNamespace(**review), now))  # type: ignore[arg-type]
        if found is None:
            return row
        return {**row, "connector_setup": {"name": found, "is_local": True, "setup_reason": None}}

    def approval_desktop_notified_at(self, request_id: str) -> str | None:
        group = self.rows[request_id]["queue_group_id"]
        for other, row in self.rows.items():
            if group is not None and row["queue_group_id"] == group and other in self.notified:
                return self.notified[other]
        return self.notified.get(request_id)


def _native_request(harness: str, payload: dict[str, object], review: dict[str, object], **_k: object) -> dict:
    """The request the resident builds from the ``review_request`` query, reduced to what these tests read."""

    request_id = review["request_id"]
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    return {
        "request_id": request_id,
        "harness": harness,
        "artifact_id": f"{harness}:native-pretool:Bash",
        "artifact_name": "Bash",
        "artifact_hash": review["review_binding"] or request_id,
        "policy_action": "review",
        "recommended_scope": "artifact",
        "changed_fields": ["native_pre_tool"],
        "source_scope": "harness",
        "config_path": review["guard_home"],
        "review_command": f"hol-guard approvals approve {request_id}",
        "approval_url": f"{review['approval_center_url']}/requests/{request_id}",
        "workspace": None,
        "artifact_type": "tool_call",
        "launch_target": tool_input["command"],
        "risk_summary": "Needs review.",
        "action_envelope_json": {},
        "raw_command_text": tool_input["command"],
        "queue_group_id": review["queue_group_id"],
    }


def _queue(monkeypatch: pytest.MonkeyPatch, store: _QueueStore, request_id: str, *, unrecognised: bool = True) -> None:
    monkeypatch.setattr(review.uuid, "uuid4", lambda: SimpleNamespace(hex=request_id))
    for name, value in {
        "native_review_policy_binding": lambda **_k: None,
        "native_review_hint_ask": lambda *_a, **_k: None,
        "native_review_query": _native_request,
    }.items():
        monkeypatch.setattr(review, name, value)
    queued = review.queue_native_pre_tool_review(
        store,
        harness="codex",
        payload={"tool_name": "Bash", "tool_input": {"command": "lanectl status"}},
        native_result={"reason": "Guard could not prove this command is read-only."},
        native_receipt=None,
        workspace=None,
        guard_home=Path("/nonexistent-guard-home"),
        exact_token=None,
        review_binding="binding",
        approval_center_url="http://127.0.0.1:4781",
        connector_lookup={"command": "lanectl status"} if unrecognised else None,
    )
    assert queued is not None


def test_a_queued_native_connector_review_raises_one_setup_notice(
    sent: list[object], monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _QueueStore()

    _queue(monkeypatch, store, "n-1")
    _queue(monkeypatch, store, "n-2")

    assert [note.request_id for note in sent] == ["n-1"]  # type: ignore[attr-defined]
    assert sent[0].title == "HOL Guard: a connector needs setup"  # type: ignore[attr-defined]
    assert sent[0].message == "Codex is waiting on a connector Guard has not set up yet: lanectl"  # type: ignore[attr-defined]


def test_a_native_review_without_a_connector_raises_no_setup_notice(
    sent: list[object], monkeypatch: pytest.MonkeyPatch
) -> None:
    _queue(monkeypatch, _QueueStore(), "o-1", unrecognised=False)
    _queue(monkeypatch, _QueueStore(connector=None), "o-2")

    assert sent == []
