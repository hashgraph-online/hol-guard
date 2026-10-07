"""Preparation inspects the existing native selection without repairing it."""

import time

import pytest

from codex_plugin_scanner.guard import codex_hook_repair_native as inspection
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.runtime_transition import TransitionError

from .test_codex_publication_preparation import _tree


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


@pytest.mark.parametrize("mode", ["off", "shadow"])
def test_non_enforcing_mode_cannot_inspect_repair_native(native_hook_force, monkeypatch, mode):
    monkeypatch.setenv("HOL_GUARD_NATIVE", mode)
    launched = []
    monkeypatch.setattr(inspection, "run_isolated_hook_process", lambda *args, **kwargs: launched.append(args))
    with pytest.raises(TransitionError, match="native_mode_invalid"):
        inspection.inspect_codex_repair_native_runtime(deadline_monotonic=time.monotonic() + 5)
    assert launched == []


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
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(comparison))
    before = _tree(tmp_path)
    with pytest.raises(CodexHookIntegrityError):
        inspection.inspect_codex_repair_native_runtime(deadline_monotonic=time.monotonic() + 5)
    assert _tree(tmp_path) == before


def test_probe_receives_original_short_parent_and_detects_changed_binary(native_hook_force, tmp_path, monkeypatch):
    comparison = tmp_path / "native-comparison"
    comparison.write_bytes(native_hook_force.read_bytes())
    comparison.chmod(0o700)
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(comparison))
    real_probe = inspection.run_isolated_hook_process
    parent = time.monotonic() + 0.8
    deadlines = []

    def changed_after_probe(*args, **kwargs):
        deadlines.append(kwargs["deadline_monotonic"])
        result = real_probe(*args, **kwargs)
        comparison.write_bytes(b"foreign native fixture generation")
        return result

    monkeypatch.setattr(inspection, "run_isolated_hook_process", changed_after_probe)
    with pytest.raises(TransitionError, match="native_runtime_generation_changed"):
        inspection.inspect_codex_repair_native_runtime(deadline_monotonic=parent)
    assert deadlines == [parent]
    assert comparison.read_bytes() == b"foreign native fixture generation"


def test_bundled_manifest_admission_precedes_native_probe(native_hook_force, tmp_path, monkeypatch):
    comparison = tmp_path / "unmanifested-native"
    comparison.write_bytes(native_hook_force.read_bytes())
    comparison.chmod(0o700)
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(comparison))
    monkeypatch.setattr(inspection.native, "_is_bundled_candidate", lambda _path: True)
    launched = []
    monkeypatch.setattr(inspection, "run_isolated_hook_process", lambda *args, **kwargs: launched.append(args))
    with pytest.raises(TransitionError, match="native_manifest_missing"):
        inspection.inspect_codex_repair_native_runtime(deadline_monotonic=time.monotonic() + 5)
    assert launched == []
