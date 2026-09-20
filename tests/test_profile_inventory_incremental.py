"""Collector control tests cannot qualify or replace installed runtime work."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts import profile_inventory_incremental as collector


class Resources:
    def __enter__(self) -> Resources:
        return self

    def __exit__(self, *exception: object) -> None:
        pass

    def report(self, *, attempted: int) -> dict[str, object]:
        return {"attempted": attempted, "scope": "unit_control_only"}


@pytest.mark.parametrize("failed_count", [None, 24, 128, 486])
def test_all_declared_cells_retain_terminal_outcomes_after_failure(
    tmp_path: Path, monkeypatch: Any, failed_count: int | None
) -> None:
    calls: list[int] = []
    monkeypatch.setattr(collector, "_clear_proof_overrides", lambda: None)
    monkeypatch.setattr(collector, "_runtime_summary", lambda runtime: {"test_identity": "unit_control_only"})
    monkeypatch.setattr(collector, "ResourceSampler", Resources)

    def work(root: Path, count: int, ledger: Any) -> dict[str, object]:
        calls.append(count)
        if count == failed_count:
            raise RuntimeError("PRIVATE-COLLECTOR-ERROR-MESSAGE")
        return {"count": count, "passed": True, "unit_control_only": True}

    monkeypatch.setattr(collector, "run_inventory_witness", work)
    path = tmp_path / "ledger.jsonl"
    report = collector.run_incremental_sweep(tmp_path / "unused-runtime", raw_file=path)
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert calls == [24, 128, 486]
    assert [row["count"] for row in rows if row["kind"] == "cell_offer"] == calls
    terminals = [row for row in rows if row["kind"] == "cell_terminal"]
    assert [row["count"] for row in terminals] == calls
    assert [row["count"] for row in terminals if not row["passed"]] == ([] if failed_count is None else [failed_count])
    assert report["implemented_checks_passed"] is (failed_count is None)
    assert report["headline_timing_eligible"] is False
    assert report["full_rsp_130_qualification"] is False
    assert report["identity_unchanged"] is True
    assert "PRIVATE-COLLECTOR" not in path.read_text()
    assert "PRIVATE-COLLECTOR" not in json.dumps(report)


def test_changed_installed_identity_rejects_apparently_successful_cells(tmp_path: Path, monkeypatch: Any) -> None:
    identities = iter(({"installed_package_sha256": "a" * 64}, {"installed_package_sha256": "b" * 64}))
    monkeypatch.setattr(collector, "_clear_proof_overrides", lambda: None)
    monkeypatch.setattr(collector, "_runtime_summary", lambda runtime: next(identities))
    monkeypatch.setattr(collector, "ResourceSampler", Resources)
    monkeypatch.setattr(
        collector, "run_inventory_witness", lambda root, count, ledger: {"count": count, "passed": True}
    )
    path = tmp_path / "ledger.jsonl"
    report = collector.run_incremental_sweep(tmp_path / "unused-runtime", raw_file=path)
    assert report["identity_unchanged"] is False
    assert report["implemented_checks_passed"] is False
    after = json.loads(path.read_text().splitlines()[-1])
    assert after["kind"] == "identity_after"
    assert after["matches_before"] is False


def test_existing_ledger_is_never_overwritten(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(collector, "_clear_proof_overrides", lambda: None)
    monkeypatch.setattr(collector, "_runtime_summary", lambda runtime: {})
    path = tmp_path / "ledger.jsonl"
    path.write_text("retained prior evidence\n")
    with pytest.raises(FileExistsError):
        collector.run_incremental_sweep(tmp_path / "unused-runtime", raw_file=path)
    assert path.read_text() == "retained prior evidence\n"


def test_changed_collector_source_rejects_apparently_successful_cells(tmp_path: Path, monkeypatch: Any) -> None:
    definitions = iter(({"sha256": "a" * 64}, {"sha256": "b" * 64}))
    monkeypatch.setattr(collector, "_clear_proof_overrides", lambda: None)
    monkeypatch.setattr(collector, "_runtime_summary", lambda runtime: {"test_identity": "unit_control_only"})
    monkeypatch.setattr(collector, "_definition", lambda: next(definitions))
    monkeypatch.setattr(collector, "ResourceSampler", Resources)
    monkeypatch.setattr(
        collector, "run_inventory_witness", lambda root, count, ledger: {"count": count, "passed": True}
    )
    path = tmp_path / "ledger.jsonl"
    report = collector.run_incremental_sweep(tmp_path / "unused-runtime", raw_file=path)
    assert report["definition_unchanged"] is False
    assert report["implemented_checks_passed"] is False
    after = json.loads(path.read_text().splitlines()[-1])
    assert after["collector_matches_before"] is False
