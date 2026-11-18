"""Preparation inspects the existing native selection without repairing it."""

import os
import time

import pytest

from codex_plugin_scanner.guard import codex_hook_repair_native as inspection
from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.native_runner_authority import native_runner_authority
from codex_plugin_scanner.guard.runtime_transition import TransitionError

from .test_codex_publication_preparation import _tree


class _BundledView:
    """``native_runtime`` as the inspection reads it, with every candidate bundled."""

    def __getattr__(self, name: str) -> object:
        return getattr(native_runtime, name)

    @staticmethod
    def _is_bundled_candidate(_path: object) -> bool:
        return True


class _SelectedView(_BundledView):
    """``native_runtime`` with only ``selected`` offered for inspection.

    The resident that answers the runtime's deadline and comparison ops keeps
    running the original binary, so a test can make the inspected file change
    or lose its execute bit without taking the resident away.
    """

    def __init__(self, selected: object) -> None:
        self._selected = selected

    def _runtime_candidates(self) -> tuple[object, ...]:
        return (self._selected,)

    def _is_bundled_candidate(self, _path: object) -> bool:
        return False


def test_actual_native_inspection_is_read_only(native_hook_force, tmp_path):
    before = _tree(tmp_path)
    metadata = native_hook_force.stat()
    identity = inspection.inspect_codex_repair_native_runtime(deadline_monotonic=time.monotonic() + 5)
    assert identity.path == native_hook_force
    assert identity.size == metadata.st_size
    assert identity.mtime_ns == metadata.st_mtime_ns
    after = native_hook_force.stat()
    # Reads may update atime; execution permission and artifact identity must
    # remain unchanged.
    assert (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) == (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    assert _tree(tmp_path) == before


def test_expired_parent_does_not_launch_a_new_native_probe(native_hook_force, monkeypatch):
    launched = []
    monkeypatch.setattr(inspection, "run_isolated_hook_process", lambda *args, **kwargs: launched.append(args))
    with pytest.raises(TransitionError, match="deadline_exceeded"):
        inspection.inspect_codex_repair_native_runtime(deadline_monotonic=time.monotonic() - 1)
    assert launched == []


def test_inspection_never_restores_a_missing_execute_bit(native_hook_force, tmp_path, monkeypatch):
    comparison = tmp_path / "non-executable-native"
    comparison.write_bytes(native_hook_force.read_bytes())
    comparison.chmod(0o400)
    monkeypatch.setattr(inspection, "native", _SelectedView(comparison))
    before = _tree(tmp_path)
    with pytest.raises(CodexHookIntegrityError):
        inspection.inspect_codex_repair_native_runtime(deadline_monotonic=time.monotonic() + 5)
    assert _tree(tmp_path) == before


def test_probe_receives_original_short_parent_and_detects_changed_binary(native_hook_force, tmp_path, monkeypatch):
    comparison = tmp_path / "native-comparison"
    comparison.write_bytes(native_hook_force.read_bytes())
    comparison.chmod(0o700)
    monkeypatch.setattr(inspection, "native", _SelectedView(comparison))
    # Start the resident first, so the short parent covers only the inspection.
    native_runner_authority("transition_files", {"op": "lease_check", "lease": "warm"})
    real_probe = inspection.run_isolated_hook_process
    parent = time.monotonic() + 5
    deadlines = []

    def changed_after_probe(*args, **kwargs):
        deadlines.append(kwargs["deadline_monotonic"])
        result = real_probe(*args, **kwargs)
        # Publish a new inode rather than writing into the inspected file.
        replacement = tmp_path / "native-replacement"
        replacement.write_bytes(b"foreign native fixture generation")
        replacement.chmod(0o700)
        os.replace(replacement, comparison)
        return result

    monkeypatch.setattr(inspection, "run_isolated_hook_process", changed_after_probe)
    with pytest.raises(TransitionError, match="native_runtime_generation_changed"):
        inspection.inspect_codex_repair_native_runtime(deadline_monotonic=parent)
    # Pinning a debug binary can take most of a second on a loaded runner, so
    # the parent is long and the probe must get the shorter one-second cap.
    assert len(deadlines) == 1 and deadlines[0] < parent
    assert comparison.read_bytes() == b"foreign native fixture generation"


def test_bundled_manifest_admission_precedes_native_probe(native_hook_force, tmp_path, monkeypatch):
    comparison = tmp_path / "unmanifested-native"
    comparison.write_bytes(native_hook_force.read_bytes())
    comparison.chmod(0o700)
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(comparison))
    # Only the inspection sees the copy as bundled; the resident it asks to
    # compare files keeps the ordinary admission.
    monkeypatch.setattr(inspection, "native", _BundledView())
    launched = []
    monkeypatch.setattr(inspection, "run_isolated_hook_process", lambda *args, **kwargs: launched.append(args))
    with pytest.raises(TransitionError, match="native_manifest_missing"):
        inspection.inspect_codex_repair_native_runtime(deadline_monotonic=time.monotonic() + 5)
    assert launched == []
