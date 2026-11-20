"""Another runtime's resident scope never withdraws or outranks this runtime's ACK."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot_publisher import (
    NativePolicySnapshotPublisher,
    _same_resident_paths,
)
from codex_plugin_scanner.guard.store import GuardStore

LIVE_DIGEST = "1234567890abcdef" + "0" * 48
LIVE_SCOPE = "resident-v3-1234567890abcdef"
FOREIGN_SCOPE = "resident-v3-fedcba0987654321"


@pytest.fixture
def publisher(tmp_path: Path):
    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path / "guard"))
    state = publisher.guard_home / "native-runtime"
    state.mkdir(mode=0o700, exist_ok=True)
    for scope in (LIVE_SCOPE, FOREIGN_SCOPE):
        (state / scope).mkdir(mode=0o700)
    publisher._last_runtime_status = SimpleNamespace(identity=SimpleNamespace(sha256=LIVE_DIGEST))
    try:
        yield publisher
    finally:
        publisher.close()


def generation(publisher, scope: str, value: int) -> Path:
    path = publisher.guard_home / "native-runtime" / scope / f"generation-{value:020d}.json"
    path.write_text("{}", encoding="utf-8")
    return path


def test_foreign_scope_restart_leaves_the_fingerprint_unchanged(publisher):
    generation(publisher, LIVE_SCOPE, 1)
    old = generation(publisher, FOREIGN_SCOPE, 4)
    before = publisher._current_resident_fingerprint()
    old.unlink()
    generation(publisher, FOREIGN_SCOPE, 5)
    assert publisher._current_resident_fingerprint() == before


def test_foreign_scope_generation_does_not_outrank_the_acknowledging_resident(publisher):
    before = publisher._current_resident_fingerprint()
    generation(publisher, LIVE_SCOPE, 1)
    generation(publisher, FOREIGN_SCOPE, 9)
    observed = publisher._current_resident_fingerprint()
    accepted = publisher._confirm_resident_fingerprint(before, observed, 1, publisher._resident_directory_fingerprint())
    assert accepted == observed


def test_live_scope_restart_still_changes_the_resident_paths(publisher):
    old = generation(publisher, LIVE_SCOPE, 1)
    before = publisher._current_resident_fingerprint()
    old.unlink()
    generation(publisher, LIVE_SCOPE, 2)
    assert not _same_resident_paths(before, publisher._current_resident_fingerprint())


def test_a_new_or_removed_scope_still_changes_the_resident_paths(publisher):
    before = publisher._current_resident_fingerprint()
    (publisher.guard_home / "native-runtime" / "resident-v3-0000111122223333").mkdir(mode=0o700)
    after = publisher._current_resident_fingerprint()
    assert not _same_resident_paths(before, after)
    (publisher.guard_home / "native-runtime" / FOREIGN_SCOPE).rmdir()
    assert not publisher._resident_paths_match(after)


def test_unknown_runtime_observes_every_scope(publisher):
    publisher._last_runtime_status = None
    generation(publisher, FOREIGN_SCOPE, 3)
    assert any(
        path.startswith(f"{FOREIGN_SCOPE}/generation-")
        for path, _mtime, _size in publisher._current_resident_fingerprint()
    )
