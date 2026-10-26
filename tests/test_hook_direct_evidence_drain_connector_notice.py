"""The drain raises the setup notice for a connector-setup review the resident queued."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import approvals, native_decision_receipt
from codex_plugin_scanner.guard.daemon import hook_native_cli_observer
from codex_plugin_scanner.guard.daemon.hook_direct_evidence_drain import record_direct_hook_evidence
from tests.test_hook_direct_evidence_drain import _Host, _record

QUEUED = {
    "request_id": "r-1",
    "harness": "codex",
    "approval_url": "http://127.0.0.1:4781/requests/r-1",
    "queue_group_id": "connector:" + "a" * 64 + ":0123456789abcdef",
}


class _Store:
    def __init__(self, rows: Mapping[str, dict[str, object]]) -> None:
        self.rows = rows
        self.looked_up: list[str] = []

    def get_approval_request(self, request_id: str) -> dict[str, object] | None:
        self.looked_up.append(request_id)
        return self.rows.get(request_id)


@pytest.fixture
def notified(monkeypatch: pytest.MonkeyPatch) -> list[tuple[object, Mapping[str, object], str]]:
    calls: list[tuple[object, Mapping[str, object], str]] = []
    monkeypatch.setattr(native_decision_receipt, "validate_native_decision_receipt", lambda receipt: receipt)
    monkeypatch.setattr(hook_native_cli_observer, "observe_native_pre_tool_cli", lambda store, **values: None)
    monkeypatch.setattr(
        approvals,
        "notify_connector_setup",
        lambda store, queued, *, connector_name: calls.append((store, queued, connector_name)),
    )
    return calls


def test_a_queued_connector_review_raises_its_notice_from_the_stored_row(
    tmp_path: Path, notified: list[tuple[object, Mapping[str, object], str]]
) -> None:
    store = _Store({"r-1": dict(QUEUED)})
    host = _Host(tmp_path, store=store)
    record = _record(connector_setup_notice={"request_id": "r-1", "connector_name": "acme"})

    assert record_direct_hook_evidence(host, record)

    assert store.looked_up == ["r-1"]
    assert notified == [(store, QUEUED, "acme")]


@pytest.mark.parametrize(
    "notice",
    [
        None,
        "r-1",
        {"request_id": "r-1"},
        {"request_id": "", "connector_name": "acme"},
        {"request_id": "r-1", "connector_name": ""},
        {"request_id": 1, "connector_name": "acme"},
    ],
)
def test_a_missing_or_malformed_notice_raises_nothing(
    tmp_path: Path, notified: list[tuple[object, Mapping[str, object], str]], notice: object
) -> None:
    store = _Store({"r-1": dict(QUEUED)})
    host = _Host(tmp_path, store=store)
    record = _record() if notice is None else _record(connector_setup_notice=notice)

    assert record_direct_hook_evidence(host, record)

    assert store.looked_up == []
    assert notified == []


def test_a_row_the_store_no_longer_holds_raises_nothing(
    tmp_path: Path, notified: list[tuple[object, Mapping[str, object], str]]
) -> None:
    store = _Store({})
    host = _Host(tmp_path, store=store)
    record = _record(connector_setup_notice={"request_id": "r-1", "connector_name": "acme"})

    assert record_direct_hook_evidence(host, record)

    assert store.looked_up == ["r-1"]
    assert notified == []


def test_a_failing_notice_does_not_fail_the_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_decision_receipt, "validate_native_decision_receipt", lambda receipt: receipt)
    monkeypatch.setattr(hook_native_cli_observer, "observe_native_pre_tool_cli", lambda store, **values: None)

    def fail(store: object, queued: Mapping[str, object], *, connector_name: str) -> None:
        raise RuntimeError("notifier unavailable")

    monkeypatch.setattr(approvals, "notify_connector_setup", fail)
    host = _Host(tmp_path, store=_Store({"r-1": dict(QUEUED)}))
    record = _record(connector_setup_notice={"request_id": "r-1", "connector_name": "acme"})

    assert record_direct_hook_evidence(host, record)
