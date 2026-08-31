from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot import (
    NativePolicySnapshotError,
    native_policy_snapshot,
)


def _snapshot(guard_home: Path, *, digest: str, observe: bool = False) -> dict[str, object]:
    return native_policy_snapshot(guard_home=guard_home, rule_digest=digest, observe_mode=observe)


def test_generation_increases_when_effective_policy_changes(tmp_path: Path) -> None:
    first = _snapshot(tmp_path, digest="a" * 64)
    second = _snapshot(tmp_path, digest="a" * 64, observe=True)
    third = _snapshot(tmp_path, digest="b" * 64, observe=True)

    assert first["generation"] == 1
    assert second["generation"] == 2
    assert third["generation"] == 3


def test_concurrent_policy_changes_never_reuse_a_generation(tmp_path: Path) -> None:
    _snapshot(tmp_path, digest="a" * 64)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda digest: _snapshot(tmp_path, digest=digest),
                ("b" * 64, "c" * 64),
            )
        )

    assert sorted(result["generation"] for result in results) == [2, 3]


def test_corrupt_generation_state_fails_closed_instead_of_resetting_floor(tmp_path: Path) -> None:
    state_path = tmp_path / "native-policy-generation.json"
    state_path.write_text('{"generation":99,"policy_digest":"not-a-digest"}', encoding="utf-8")
    state_path.chmod(0o600)

    with pytest.raises(NativePolicySnapshotError, match="native_policy_generation_state_invalid"):
        _snapshot(tmp_path, digest="a" * 64)

    assert json.loads(state_path.read_text(encoding="utf-8"))["generation"] == 99


def test_missing_generation_state_after_initialization_fails_closed(tmp_path: Path) -> None:
    _snapshot(tmp_path, digest="a" * 64)
    (tmp_path / "native-policy-generation.json").unlink()

    with pytest.raises(NativePolicySnapshotError, match="native_policy_generation_state_missing"):
        _snapshot(tmp_path, digest="b" * 64)


def test_owner_controlled_readable_guard_home_is_supported(tmp_path: Path) -> None:
    tmp_path.chmod(0o755)

    assert _snapshot(tmp_path, digest="a" * 64)["generation"] == 1


def test_unchanged_policy_does_not_repeat_durable_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    first = _snapshot(tmp_path, digest="a" * 64)
    fsync_calls = 0
    real_fsync = os.fsync

    def counting_fsync(descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", counting_fsync)

    assert _snapshot(tmp_path, digest="a" * 64) == first
    assert fsync_calls == 0


def test_initialized_unchanged_policy_does_not_reacquire_generation_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _snapshot(tmp_path, digest="a" * 64)

    def unexpected_lock(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("unchanged initialized policy reacquired generation lock")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_policy_snapshot._generation_lock",
        unexpected_lock,
    )

    assert _snapshot(tmp_path, digest="a" * 64) == first


@pytest.mark.skipif(os.name == "nt", reason="POSIX flock contract")
def test_posix_generation_lock_honors_hook_deadline(tmp_path: Path) -> None:
    import fcntl

    lock_path = tmp_path / "native-policy-generation.lock"
    lock_path.touch(mode=0o600)
    lock_path.chmod(0o600)
    with lock_path.open("w+b") as holder:
        holder.write(b"0")
        holder.flush()
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(NativePolicySnapshotError, match="native_policy_generation_lock_timeout"):
            native_policy_snapshot(
                guard_home=tmp_path,
                rule_digest="a" * 64,
                observe_mode=False,
                deadline_monotonic=time.monotonic() + 0.02,
            )


def test_group_writable_guard_home_is_rejected(tmp_path: Path) -> None:
    tmp_path.chmod(0o770)

    with pytest.raises(NativePolicySnapshotError, match="native_policy_generation_home_invalid"):
        _snapshot(tmp_path, digest="a" * 64)
