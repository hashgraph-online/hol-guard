"""Preparation inspects the existing native selection without repairing it."""

import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_repair_native as inspection
from codex_plugin_scanner.guard import native_runtime
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


def _capture(monkeypatch, answer):
    sent = {}

    def fake(**facts):
        sent.update(facts)
        return answer

    monkeypatch.setattr(inspection, "inspect_runtime", fake)
    return sent


def test_inspection_sends_the_install_facts_only_this_process_holds(monkeypatch, tmp_path):
    sent = _capture(monkeypatch, {"path": str(tmp_path / "rt"), "size": 3, "mtime_ns": 7, "sha256": "ab" * 32})
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(tmp_path / "override"))
    deadline = time.monotonic() + 5
    identity = inspection.inspect_codex_repair_native_runtime(deadline_monotonic=deadline)
    assert (identity.path, identity.size, identity.mtime_ns, identity.sha256) == (
        tmp_path / "rt",
        3,
        7,
        "ab" * 32,
    )
    assert sent["deadline"] == deadline
    assert sent["mode"] == "force"
    assert sent["binary_override"] == str(tmp_path / "override")
    assert sent["bundled"] == native_runtime._bundled_runtime_candidate()
    assert sent["package_version"] == native_runtime._python_package_version()
    assert Path(sent["checker"]).name == "group_write_trust.py"
    assert sent["distribution"] == native_runtime._distribution_candidates()


def test_inspection_offers_distribution_runtimes_in_force_mode_only(monkeypatch, tmp_path):
    answer = {"path": str(tmp_path / "rt"), "size": 3, "mtime_ns": 7, "sha256": "ab" * 32}
    sent = _capture(monkeypatch, answer)
    monkeypatch.setattr(native_runtime, "_distribution_candidates", lambda: (tmp_path / "dist",))
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    inspection.inspect_codex_repair_native_runtime(deadline_monotonic=time.monotonic() + 5)
    assert tuple(sent["distribution"]) == ()
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    inspection.inspect_codex_repair_native_runtime(deadline_monotonic=time.monotonic() + 5)
    assert tuple(sent["distribution"]) == (tmp_path / "dist",)


@pytest.mark.parametrize(
    "answer",
    [
        {},
        {"path": 1, "size": 3, "mtime_ns": 7, "sha256": "ab"},
        {"path": "/x", "size": True, "mtime_ns": 7, "sha256": "ab"},
        {"path": "/x", "size": 3, "mtime_ns": "7", "sha256": "ab"},
        {"path": "/x", "size": 3, "mtime_ns": 7, "sha256": None},
    ],
)
def test_inspection_refuses_an_identity_the_runtime_did_not_fully_give(monkeypatch, answer):
    _capture(monkeypatch, answer)
    with pytest.raises(TransitionError, match="native_transition_invalid"):
        inspection.inspect_codex_repair_native_runtime(deadline_monotonic=time.monotonic() + 5)
