"""The Guard home retention sweeps run in the native runtime.

The retention behaviour itself is covered by the Rust tests in
``rust/crates/guard-runtime/src/storage_retention_tests.rs``; these tests pin
the requests the shims send and how they read the answers.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.storage_retention import (
    prune_quarantined_store_snapshots,
    prune_stale_update_staging,
    quarantined_store_summary,
)

_EMPTY_SUMMARY = {"count": 0, "total_bytes": 0, "newest_quarantined_at": None, "forensic_record_count": 0}


class _Runtime:
    def __init__(self, answer: dict[str, object] | None) -> None:
        self.answer_value = answer
        self.requests: list[dict[str, object]] = []

    def answer(
        self,
        feature: str,
        command: str,
        request: dict[str, object],
        *,
        output_limit: int,
        timeout_seconds: float,
    ) -> dict[str, object] | None:
        assert (feature, command) == ("native-storage-retention-v1", "storage-retention")
        assert output_limit > 0
        assert timeout_seconds > 0
        self.requests.append(request)
        return self.answer_value


def _install(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None) -> _Runtime:
    fake = _Runtime(answer)
    monkeypatch.setattr("codex_plugin_scanner.guard.mdm.runtime_request.runtime_answer", fake.answer)
    return fake


def test_quarantine_prune_sends_the_retention_policy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = _install(monkeypatch, {"removed": 3})

    assert prune_quarantined_store_snapshots(tmp_path) == 3
    assert (
        prune_quarantined_store_snapshots(
            tmp_path, now=12.5, min_keep=-4, max_age=timedelta(seconds=90), max_total_bytes=250
        )
        == 3
    )

    assert fake.requests == [
        {
            "schema": "storage-retention.v1",
            "op": "quarantine-prune",
            "guard_home": str(tmp_path.absolute()),
            "min_keep": 2,
            "max_age_seconds": 7 * 24 * 60 * 60.0,
            "max_total_bytes": 2 * 1024**3,
        },
        {
            "schema": "storage-retention.v1",
            "op": "quarantine-prune",
            "guard_home": str(tmp_path.absolute()),
            "min_keep": 0,
            "max_age_seconds": 90.0,
            "max_total_bytes": 250,
            "now": 12.5,
        },
    ]


@pytest.mark.parametrize("answer", [None, {}, {"removed": "3"}, {"removed": True}])
def test_quarantine_prune_without_a_count_removed_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: dict[str, object] | None
) -> None:
    _install(monkeypatch, answer)
    assert prune_quarantined_store_snapshots(tmp_path) == 0


def test_quarantine_summary_returns_the_runtime_summary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    summary: dict[str, object] = {
        "count": 2,
        "total_bytes": 64,
        "newest_quarantined_at": "2026-09-05T13:29:08.303335+00:00",
        "forensic_record_count": 2,
    }
    fake = _install(monkeypatch, summary)

    assert quarantined_store_summary(tmp_path) == summary
    assert fake.requests == [
        {"schema": "storage-retention.v1", "op": "quarantine-summary", "guard_home": str(tmp_path.absolute())}
    ]


@pytest.mark.parametrize("answer", [None, {}, {"count": 1}])
def test_quarantine_summary_reads_empty_without_a_runtime_answer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: dict[str, object] | None
) -> None:
    _install(monkeypatch, answer)
    assert quarantined_store_summary(tmp_path) == _EMPTY_SUMMARY


def test_staging_prune_sends_the_age_gate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = _install(monkeypatch, {})

    prune_stale_update_staging(tmp_path / "guard-home")
    prune_stale_update_staging(tmp_path / "guard-home", age_seconds=60)

    home = str((tmp_path / "guard-home").absolute())
    assert fake.requests == [
        {"schema": "storage-retention.v1", "op": "staging-prune", "guard_home": home, "age_seconds": 604800.0},
        {"schema": "storage-retention.v1", "op": "staging-prune", "guard_home": home, "age_seconds": 60.0},
    ]

