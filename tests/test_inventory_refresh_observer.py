"""Qualification observation must preserve original calls and private data."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import aibom_cli
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.store import GuardStore
from scripts.inventory_refresh_observer import InventoryObserver


class Ledger:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def write(self, row: Any) -> None:
        self.rows.append(dict(row))


def test_forwarder_preserves_identity_call_count_and_restores_on_exception(tmp_path: Path, monkeypatch: Any) -> None:
    ledger = Ledger()
    store = GuardStore(tmp_path / "guard")
    marker = HarnessContext(tmp_path / "home", tmp_path / "workspace", store.guard_home)
    calls: list[object] = []
    result: list[object] = []
    error = RuntimeError("PRIVATE-SCANNER-MESSAGE-AND-PATH")

    def original(context: object) -> list[object]:
        calls.append(context)
        if len(calls) == 3:
            raise error
        return result

    monkeypatch.setattr(aibom_cli, "detect_all", original)
    observer = InventoryObserver(store, ledger)
    with pytest.raises(RuntimeError) as captured, observer:
        assert aibom_cli.detect_all(marker) is result
        assert ledger.rows == []
        with observer.refresh("owned"):
            assert aibom_cli.detect_all(marker) is result
            aibom_cli.detect_all(marker)
    assert captured.value is error
    assert calls == [marker, marker, marker]
    assert aibom_cli.detect_all is original
    assert "detect_all" not in store.__dict__
    assert "record_inventory_artifact" not in store.__dict__
    terminals = [row for row in ledger.rows if row["kind"] == "span_terminal"]
    assert [row["state"] for row in terminals] == ["completed", "failed"]
    assert "PRIVATE-SCANNER" not in json.dumps(ledger.rows)
    assert observer.report()["all_wrappers_restored"] is True


def test_overlapping_observer_refused_without_replacing_owned_wrappers(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    previous = aibom_cli.detect_all
    with InventoryObserver(store, Ledger()):
        active = aibom_cli.detect_all
        with pytest.raises(RuntimeError, match="already active"), InventoryObserver(store, Ledger()):
            pytest.fail("overlapping observer acquired ownership")
        assert aibom_cli.detect_all is active
    assert aibom_cli.detect_all is previous


def test_nested_spans_retain_relationship_and_reject_nested_refresh(tmp_path: Path) -> None:
    ledger = Ledger()
    with (
        InventoryObserver(GuardStore(tmp_path / "guard"), ledger) as observer,
        observer.refresh("outer"),
        observer.span("parent"),
        observer.span("child"),
        pytest.raises(RuntimeError, match="already assigned"),
        observer.refresh("other"),
    ):
        pytest.fail("nested refresh replaced owner")
    starts = [row for row in ledger.rows if row["kind"] == "span_start"]
    assert starts[1]["parent"] == starts[0]["span"]
    assert all(row["refresh"] == "outer" for row in ledger.rows)


@pytest.mark.parametrize("status", ["enabled", "skipped", "unavailable", "failed", "timed_out"])
def test_scanner_outcomes_keep_local_provenance_without_messages(tmp_path: Path, status: str) -> None:
    ledger = Ledger()
    run = SimpleNamespace(
        source="cisco-skill-scanner",
        status=status,
        findings=(object(),),
        message="PRIVATE-SCANNER-MESSAGE",
        metadata={
            "evidenceProvenance": "client_unverified",
            "scannerResolutionSource": "local_reported",
            "scannerVerificationRequired": "guard_cloud",
            "target": "/private/fixture/secret-path",
        },
    )
    with InventoryObserver(GuardStore(tmp_path / "guard"), ledger) as observer, observer.refresh("scan"):
        observer._scanner_results((run,))
        run.metadata["evidenceProvenance"] = "verified"
        with pytest.raises(ValueError, match="provenance changed"):
            observer._scanner_results((run,))
    assert len(ledger.rows) == 1
    assert ledger.rows[0]["status"] == status
    assert ledger.rows[0]["evidence_provenance"] == "client_unverified"
    assert ledger.rows[0]["verification_required"] == "guard_cloud"
    assert "PRIVATE" not in json.dumps(ledger.rows)
    assert "secret-path" not in json.dumps(ledger.rows)
