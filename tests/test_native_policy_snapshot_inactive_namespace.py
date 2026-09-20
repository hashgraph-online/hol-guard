"""Real filesystem controls for inactive resident namespace admission.

Metadata-only controls do not stand in for native authentication. The publisher
control uses the existing signed snapshot producer with an explicit ACK double.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_resident_inputs import NativePolicySnapshotResidentInputsMixin
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _ack, _status


def _namespace(tmp_path: Path) -> tuple[NativePolicySnapshotResidentInputsMixin, Path, Path]:
    home = tmp_path / "guard-home"
    state = home / "native-runtime"
    scope = state / "resident-v3-owned"
    scope.mkdir(parents=True, mode=0o700)
    observer = NativePolicySnapshotResidentInputsMixin()
    observer.guard_home = home
    return observer, state, scope


def _generation(scope: Path, generation: int) -> Path:
    path = scope / f"generation-{generation:020}.json"
    path.write_text("{}", encoding="utf-8")
    return path


def _confirm(observer: NativePolicySnapshotResidentInputsMixin, before: Any, generation: int = 1) -> Any:
    observed = observer._current_resident_fingerprint()
    return observer._confirm_resident_fingerprint(
        before, observed, generation, observer._resident_directory_fingerprint()
    )


def test_retired_directory_accepts_first_new_generation(tmp_path: Path) -> None:
    observer, _state, scope = _namespace(tmp_path)
    retired = _generation(scope, 1)
    retired.unlink()
    before = observer._current_resident_fingerprint()
    _generation(scope, 2)
    assert _confirm(observer, before, 2) == observer._current_resident_fingerprint()


def test_first_generation_in_new_scope_remains_supported(tmp_path: Path) -> None:
    observer, _state, scope = _namespace(tmp_path)
    scope.rmdir()
    before = observer._current_resident_fingerprint()
    scope.mkdir(mode=0o700)
    _generation(scope, 1)
    assert _confirm(observer, before) == observer._current_resident_fingerprint()


def test_absent_runtime_directory_preserves_explicit_no_state_double(tmp_path: Path) -> None:
    observer = NativePolicySnapshotResidentInputsMixin()
    observer.guard_home = tmp_path
    assert observer._current_resident_fingerprint() == ()
    assert observer._confirm_resident_fingerprint((), (), 1, None) == ()


def test_stable_generation_is_admitted(tmp_path: Path) -> None:
    observer, _state, scope = _namespace(tmp_path)
    _generation(scope, 1)
    before = observer._current_resident_fingerprint()
    assert _confirm(observer, before) == before


def test_changed_live_generation_is_refused(tmp_path: Path) -> None:
    observer, _state, scope = _namespace(tmp_path)
    _generation(scope, 1)
    before = observer._current_resident_fingerprint()
    _generation(scope, 2)
    assert _confirm(observer, before, 2) is None


def test_first_generation_still_requires_newest_ack_generation(tmp_path: Path) -> None:
    observer, _state, scope = _namespace(tmp_path)
    before = observer._current_resident_fingerprint()
    _generation(scope, 2)
    assert _confirm(observer, before, 1) is None


@pytest.mark.parametrize("root_scan", [False, True])
@pytest.mark.parametrize("error_type", [PermissionError, FileNotFoundError, OSError])
def test_failed_iteration_is_not_an_empty_namespace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root_scan: bool, error_type: type[OSError]
) -> None:
    observer, state, scope = _namespace(tmp_path)
    target = state if root_scan else scope
    original = Path.iterdir

    def refused(path: Path) -> Any:
        if path == target:
            raise error_type("fixture iteration failure")
        return original(path)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "iterdir", refused)
        unobserved = observer._current_resident_fingerprint()
    _generation(scope, 1)
    observed = observer._current_resident_fingerprint()
    directory = observer._resident_directory_fingerprint()
    assert unobserved
    assert observer._confirm_resident_fingerprint(unobserved, observed, 1, directory) is None
    assert observer._confirm_resident_fingerprint((), unobserved, 1, directory) is None


@pytest.mark.parametrize("root_scan", [False, True])
def test_partially_consumed_iteration_is_not_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root_scan: bool
) -> None:
    observer, state, scope = _namespace(tmp_path)
    _generation(scope, 1)
    target = state if root_scan else scope
    original = Path.iterdir

    def partial(path: Path) -> Any:
        if path != target:
            yield from original(path)
            return
        yield next(original(path))
        raise OSError("fixture mid-iteration failure")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "iterdir", partial)
        unobserved = observer._current_resident_fingerprint()
    assert observer._confirm_resident_fingerprint((), unobserved, 1, observer._resident_directory_fingerprint()) is None


def test_root_stat_permission_failure_is_not_absence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    observer, state, scope = _namespace(tmp_path)
    original = Path.lstat

    def refused(path: Path) -> os.stat_result:
        if path == state:
            raise PermissionError("fixture root stat failure")
        return original(path)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", refused)
        unobserved = observer._current_resident_fingerprint()
    _generation(scope, 1)
    assert unobserved
    assert _confirm(observer, unobserved) is None


@pytest.mark.parametrize("root_scan", [False, True])
def test_mutation_during_enumeration_is_not_a_complete_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root_scan: bool
) -> None:
    observer, state, scope = _namespace(tmp_path)
    target = state if root_scan else scope
    old_mtime = target.stat().st_mtime_ns
    original = Path.iterdir

    def mutated(path: Path) -> Any:
        yield from original(path)
        if path == target:
            (target / "fixture-namespace-change").write_text("changed", encoding="utf-8")
            os.utime(target, ns=(old_mtime + 1_000_000, old_mtime + 1_000_000))

    with monkeypatch.context() as patch:
        patch.setattr(Path, "iterdir", mutated)
        unobserved = observer._current_resident_fingerprint()
    _generation(scope, 1)
    assert _confirm(observer, unobserved) is None


@pytest.mark.parametrize("root_swap", [False, True])
def test_namespace_replacement_before_ack_is_refused(tmp_path: Path, root_swap: bool) -> None:
    observer, state, scope = _namespace(tmp_path)
    before = observer._current_resident_fingerprint()
    target = state if root_swap else scope
    metadata = target.stat()
    target.rename(tmp_path / "retired-namespace")
    target.mkdir(mode=0o700)
    if root_swap:
        scope.mkdir(mode=0o700)
    _generation(scope, 1)
    os.utime(target, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    assert _confirm(observer, before) is None


@pytest.mark.parametrize("root_swap", [False, True])
def test_namespace_replacement_after_ack_sample_is_refused(tmp_path: Path, root_swap: bool) -> None:
    observer, state, scope = _namespace(tmp_path)
    before = observer._current_resident_fingerprint()
    original_generation = _generation(scope, 1)
    generation_metadata = original_generation.stat()
    observed = observer._current_resident_fingerprint()
    directory = observer._resident_directory_fingerprint()
    state_metadata = state.stat()
    target = state if root_swap else scope
    metadata = target.stat()
    target.rename(tmp_path / "retired-namespace")
    target.mkdir(mode=0o700)
    if root_swap:
        scope.mkdir(mode=0o700)
    replacement = _generation(scope, 1)
    os.utime(replacement, ns=(generation_metadata.st_atime_ns, generation_metadata.st_mtime_ns))
    os.utime(target, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    if not root_swap:
        os.utime(state, ns=(state_metadata.st_atime_ns, state_metadata.st_mtime_ns))
        assert observer._resident_directory_fingerprint() == directory
    assert observer._confirm_resident_fingerprint(before, observed, 1, directory) is None


def test_new_generation_after_ack_sample_is_refused(tmp_path: Path) -> None:
    observer, _state, scope = _namespace(tmp_path)
    before = observer._current_resident_fingerprint()
    _generation(scope, 1)
    observed = observer._current_resident_fingerprint()
    directory = observer._resident_directory_fingerprint()
    old_mtime = scope.stat().st_mtime_ns
    _generation(scope, 2)
    os.utime(scope, ns=(old_mtime + 1_000_000, old_mtime + 1_000_000))
    assert observer._confirm_resident_fingerprint(before, observed, 1, directory) is None


@pytest.mark.parametrize("malformed", ["generation-x.json", "generation-1", "generation-.json"])
def test_malformed_generation_is_unobserved(tmp_path: Path, malformed: str) -> None:
    observer, _state, scope = _namespace(tmp_path)
    (scope / malformed).write_text("{}", encoding="utf-8")
    assert _confirm(observer, (), 1) is None


def test_symlinked_scope_is_unobserved(tmp_path: Path) -> None:
    observer, _state, scope = _namespace(tmp_path)
    scope.rmdir()
    destination = tmp_path / "different-directory"
    destination.mkdir()
    try:
        scope.symlink_to(destination, target_is_directory=True)
    except OSError:
        pytest.skip("platform cannot create owned directory symlink")
    _generation(destination, 1)
    assert _confirm(observer, (), 1) is None


def test_publisher_accepts_retained_empty_scope_after_one_push(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"v" * 32, "master-id"))
    scope = store.guard_home / "native-runtime" / "resident-v3-owned"
    scope.parent.mkdir(mode=0o700)
    scope.mkdir(mode=0o700)
    _generation(scope, 1).unlink()
    calls: list[bytes] = []

    def acknowledge(**kwargs: Any) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        calls.append(payload)
        _generation(scope, 1)
        return _ack(payload)

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=_status, client_request=acknowledge)
    try:
        publisher._publish_once()
        assert len(calls) == 1, publisher.last_error
        assert publisher.is_ready()
        assert publisher.current_snapshot() is not None
        assert publisher.last_error is None
    finally:
        publisher.close()
