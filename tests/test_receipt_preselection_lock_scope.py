"""Proposed controls for credential lock scope around local permission and selection."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import receipt_sync_authority as authority
from codex_plugin_scanner.guard.runtime import runner
from tests.test_receipt_sync_authority import CURSOR, NOW, REDACTION, RELAXATION, _attempt, _complete, _ready


def test_local_withdrawal_while_waiting_for_credential_lock_refuses_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = _ready(tmp_path)
    attempt = _attempt(store)
    original_lock = store.hold_oauth_credential_lock

    @contextmanager
    def withdraw_before_lock_acquisition(**kwargs: Any) -> Iterator[None]:
        (store.guard_home / "config.toml").write_text(
            'sync = false\nreceipt_redaction_level = "none"\n', encoding="utf-8"
        )
        with original_lock(**kwargs):
            yield

    monkeypatch.setattr(store, "hold_oauth_credential_lock", withdraw_before_lock_acquisition)
    completion = _complete(store, attempt)
    assert completion.preference_accepted and completion.receipt_acknowledged
    assert not completion.progress_committed
    assert store.get_sync_payload(CURSOR) is None


def test_selection_bookkeeping_holds_one_credential_lock_and_returns_its_written_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = _ready(tmp_path)
    source = authority.capture_receipt_sync_state(store).preference_state.connection
    original_lock = store.hold_oauth_credential_lock
    original_write = store.set_sync_payload
    active = False
    acquisitions = 0
    writes: list[str] = []

    @contextmanager
    def checked_lock(**kwargs: Any) -> Iterator[None]:
        nonlocal active, acquisitions
        assert not active, "nested credential capture would reacquire the advisory lock"
        with original_lock(**kwargs):
            active = True
            acquisitions += 1
            try:
                yield
            finally:
                active = False

    def checked_write(key: str, payload: dict[str, object], now: str) -> None:
        if key in {CURSOR, REDACTION, RELAXATION}:
            assert active
            writes.append(key)
        original_write(key, payload, now)

    monkeypatch.setattr(store, "hold_oauth_credential_lock", checked_lock)
    monkeypatch.setattr(store, "set_sync_payload", checked_write)
    captured, allowed, level = runner._prepare_optional_receipt_selection(store, source, synced_at=NOW)
    assert acquisitions == 1 and not active
    assert allowed and level == "partial" and captured is not None
    assert {CURSOR, REDACTION, RELAXATION} <= set(writes)
    assert captured.rows.cursor is not None and captured.rows.cursor.payload() == store.get_sync_payload(CURSOR)
    assert captured.rows.redaction is not None
    assert captured.rows.redaction.payload() == store.get_sync_payload(REDACTION)
    assert captured.rows.relaxation is not None
    assert captured.rows.relaxation.payload() == store.get_sync_payload(RELAXATION)
    assert captured.preference_state.connection.same_authority(source)
