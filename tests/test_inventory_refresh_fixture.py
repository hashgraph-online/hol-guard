"""Real distinct file changes and transparent offline transport qualification."""

from __future__ import annotations

import json
import threading
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.adapters.gemini import GeminiHarnessAdapter
from codex_plugin_scanner.guard.store import GuardStore
from scripts.inventory_refresh_fixture import (
    MUTATIONS,
    URL,
    OfflineInventoryTransport,
    identity_change,
    mutate_inputs,
)
from scripts.inventory_refresh_observer import InventoryObserver, detection_identities
from scripts.profile_inventory_refresh import fixture


class Ledger:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def write(self, row: Any) -> None:
        self.rows.append(dict(row))


def test_burst_changes_distinct_files_and_invalidates_restored_metadata(tmp_path: Path) -> None:
    context = fixture(tmp_path, 24)
    adapter = GeminiHarnessAdapter()
    before = detection_identities((adapter.detect(context),))
    ledger = Ledger()
    with InventoryObserver(GuardStore(context.guard_home), ledger) as observer:
        outcomes = mutate_inputs(context, observer)
    after = detection_identities((adapter.detect(context),))
    assert len(outcomes) == MUTATIONS
    assert all(row["state"] == "completed" for row in outcomes)
    assert all(row["metadata_preserved"] for row in outcomes[:8])
    assert identity_change(before, after) == {"changed": 16, "unchanged": 0, "added": 8, "removed": 8}
    offers = [row["mutation"] for row in ledger.rows if row["kind"] == "mutation_offer"]
    terminals = [row["mutation"] for row in ledger.rows if row["kind"] == "mutation_terminal"]
    assert offers == terminals == list(range(32))
    assert str(tmp_path) not in json.dumps(ledger.rows)


def test_transport_acknowledges_only_after_concurrent_producer_releases(tmp_path: Path) -> None:
    ledger = Ledger()
    with InventoryObserver(GuardStore(tmp_path / "guard"), ledger) as observer:
        transport = OfflineInventoryTransport(observer)
        released = threading.Event()

        def producer() -> None:
            assert transport.entered.wait(2.0)
            released.set()
            transport.release.set()

        thread = threading.Thread(target=producer)
        thread.start()
        try:
            with observer.refresh("initial_overlap"):
                request = urllib.request.Request(URL, data=b'{"events":[{},{}]}')
                with transport(request, timeout=90) as response:
                    assert json.load(response) == {"accepted": 2, "rejected": 0}
                assert released.is_set()
        finally:
            transport.release.set()
            thread.join(2.0)
        assert not thread.is_alive()
    terminal = next(row for row in ledger.rows if row["kind"] == "span_terminal")
    assert terminal["synthetic_acknowledgment"] is True
    assert terminal["external_network_used"] is False
    assert terminal["fixture_wait_ns"] >= 0
    assert "events" not in terminal


def test_transport_refuses_unowned_and_unexpected_network_without_forwarding(tmp_path: Path) -> None:
    with InventoryObserver(GuardStore(tmp_path / "guard"), Ledger()) as observer:
        transport = OfflineInventoryTransport(observer)
        request = urllib.request.Request(URL, data=b'{"events":[]}')
        with pytest.raises(RuntimeError, match="unowned"):
            transport(request, timeout=90)
        with observer.refresh("owned"), pytest.raises(RuntimeError, match="unexpected network"):
            transport(urllib.request.Request("https://example.invalid/private", data=b"{}"), timeout=90)
        assert transport.requests == 0
