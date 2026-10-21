"""A fresh resident ACK is valid after stop leaves only empty scope roots."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture
def publisher(tmp_path: Path):
    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path / "guard"))
    state = publisher.guard_home / "native-runtime"
    state.mkdir(mode=0o700, exist_ok=True)
    (state / "resident-v3-1234567890abcdef").mkdir(mode=0o700)
    try:
        yield publisher
    finally:
        publisher.close()


def generation(publisher, value: int = 7) -> Path:
    path = publisher.guard_home / "native-runtime" / "resident-v3-1234567890abcdef" / f"generation-{value:020d}.json"
    path.write_text("{}", encoding="utf-8")
    return path


def confirm(publisher, before, acknowledged: int = 7):
    observed = publisher._current_resident_fingerprint()
    return observed, publisher._confirm_resident_fingerprint(
        before, observed, acknowledged, publisher._resident_directory_fingerprint()
    )


def test_first_generation_after_contained_stop_is_accepted_in_one_publication(publisher):
    before = publisher._current_resident_fingerprint()
    assert len(before) == 1 and "/" not in before[0][0]
    generation(publisher)
    observed, accepted = confirm(publisher, before)
    assert accepted == observed


@pytest.mark.parametrize("acknowledged", [1, 6, 8])
def test_empty_roots_do_not_accept_a_stale_or_future_ack(publisher, acknowledged):
    before = publisher._current_resident_fingerprint()
    generation(publisher)
    assert confirm(publisher, before, acknowledged)[1] is None


def test_replacing_an_observed_live_generation_still_rejects_the_ack(publisher):
    old = generation(publisher, 6)
    before = publisher._current_resident_fingerprint()
    old.unlink()
    generation(publisher)
    assert confirm(publisher, before)[1] is None


def test_metadata_change_to_existing_generation_still_rejects_the_ack(publisher):
    path = generation(publisher)
    before = publisher._current_resident_fingerprint()
    path.write_text('{"changed":true}', encoding="utf-8")
    assert confirm(publisher, before)[1] is None


def test_empty_root_case_still_rechecks_generation_after_ack(publisher):
    before = publisher._current_resident_fingerprint()
    path = generation(publisher)
    observed = publisher._current_resident_fingerprint()
    directory = publisher._resident_directory_fingerprint()
    path.write_text('{"changed-after-ack":true}', encoding="utf-8")
    assert publisher._confirm_resident_fingerprint(before, observed, 7, directory) is None


def test_empty_root_case_still_rechecks_runtime_directory_after_ack(publisher):
    before = publisher._current_resident_fingerprint()
    generation(publisher)
    observed = publisher._current_resident_fingerprint()
    directory = publisher._resident_directory_fingerprint()
    state = publisher.guard_home / "native-runtime"
    (state / "unexpected-new-root").mkdir()
    metadata = state.stat()
    assert directory is not None
    os.utime(state, ns=(metadata.st_atime_ns, directory[0] + 1_000_000_000))
    assert publisher._resident_directory_fingerprint() != directory
    assert publisher._confirm_resident_fingerprint(before, observed, 7, directory) is None


def test_empty_root_case_cannot_change_scope(publisher):
    before = publisher._current_resident_fingerprint()
    generation(publisher)
    state = publisher.guard_home / "native-runtime"
    (state / "resident-v3-1234567890abcdef").rename(state / "resident-v3-fedcba0987654321")
    assert confirm(publisher, before)[1] is None


def test_changed_empty_directory_without_a_generation_cannot_open_readiness(publisher):
    before = publisher._current_resident_fingerprint()
    scope = publisher.guard_home / "native-runtime" / "resident-v3-1234567890abcdef"
    (scope / "not-a-generation").write_text("unused", encoding="utf-8")
    metadata = scope.stat()
    os.utime(scope, ns=(metadata.st_atime_ns, before[0][1] + 1_000_000_000))
    assert publisher._current_resident_fingerprint() != before
    assert confirm(publisher, before)[1] is None


def test_unchanged_live_generation_remains_accepted(publisher):
    generation(publisher)
    before = publisher._current_resident_fingerprint()
    observed, accepted = confirm(publisher, before)
    assert accepted == observed
