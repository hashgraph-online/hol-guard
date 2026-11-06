"""``hol-guard repair`` has to fix the one runtime fault the runtime cannot fix itself."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runtime, repair_engine
from codex_plugin_scanner.guard.runtime_install_repair import repair_native_runtime_install

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX execute bits")


def _bundled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int) -> Path:
    """Plant a file where Guard looks for the runtime it ships with itself."""

    target = tmp_path / "hol-guard-runtime"
    target.write_bytes(b"#!/bin/sh\nexit 0\n")
    target.chmod(mode)
    # ``_is_bundled_candidate`` compares against this, so patching it is what
    # makes the planted file Guard's own copy rather than a separate install.
    monkeypatch.setattr(native_runtime, "_bundled_runtime_candidate", lambda: target)
    monkeypatch.setattr(native_runtime, "_runtime_candidates", lambda: (target,))
    return target


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def test_a_runtime_that_lost_its_execute_bit_gets_it_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _bundled(tmp_path, monkeypatch, 0o644)

    report = repair_native_runtime_install(dry_run=False)

    assert report["outcome"] == "restored"
    assert _mode(target) & stat.S_IXUSR
    # The reported evidence is read after the write, so it describes the
    # install the user is left with rather than the one Guard found.
    assert report["candidates"] == [{"slot": "bundled", "state": "present"}]
    # The bit is all Guard controls; a `noexec` mount defeats it and the file
    # cannot show that, so the caveat is what names the remaining possibility.
    assert "noexec" in str(report["action"])


def test_repairing_an_install_twice_changes_nothing_the_second_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _bundled(tmp_path, monkeypatch, 0o644)

    repair_native_runtime_install(dry_run=False)
    restored = _mode(target)
    second = repair_native_runtime_install(dry_run=False)

    assert second["outcome"] == "healthy"
    assert second["action"] is None
    assert _mode(target) == restored


def test_a_dry_run_names_the_repair_without_touching_the_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _bundled(tmp_path, monkeypatch, 0o644)

    report = repair_native_runtime_install(dry_run=True)

    assert report["outcome"] == "planned"
    assert _mode(target) == 0o644
    assert report["candidates"] == [{"slot": "bundled", "state": "not_executable"}]


def test_a_chmod_that_cannot_take_is_reported_rather_than_claimed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _bundled(tmp_path, monkeypatch, 0o644)
    # The restore helper reports nothing and swallows its own errors, so a
    # refusal is only visible in the file. Refusing the ownership check is how
    # the launch path itself declines to touch a copy it does not trust.
    monkeypatch.setattr(native_runtime, "_trusted_owner_and_mode", lambda metadata, path: False)

    report = repair_native_runtime_install(dry_run=False)

    assert report["outcome"] == "refused"
    assert not _mode(target) & stat.S_IXUSR
    assert "without `sudo`" in str(report["action"])


def test_an_install_only_a_reinstall_can_fix_is_named_not_repaired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _bundled(tmp_path, monkeypatch, 0o777)

    report = repair_native_runtime_install(dry_run=False)

    assert report["outcome"] == "needs_reinstall"
    assert "writable" in report["summary"]
    assert "without `sudo`" in str(report["action"])
    # Guard replaces no installed binary on the user's behalf, so the file is
    # exactly as it was found.
    assert _mode(target) == 0o777


def test_an_install_that_ships_no_runtime_is_reported_without_a_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / "hol-guard-runtime"
    monkeypatch.setattr(native_runtime, "_bundled_runtime_candidate", lambda: missing)
    monkeypatch.setattr(native_runtime, "_runtime_candidates", lambda: (missing,))

    report = repair_native_runtime_install(dry_run=False)

    assert report["outcome"] == "absent"
    assert "no native runtime binary" in report["summary"]
    assert not missing.exists()


def test_the_repair_step_counts_a_restored_bit_as_a_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _bundled(tmp_path, monkeypatch, 0o644)

    step = repair_engine.repair_native_install(dry_run=False)
    report = repair_engine.build_report([step], dry_run=False)

    assert step["status"] == "changed"
    assert step["outcome"] == "restored"
    assert report["status"] == "repaired"


def test_an_install_needing_a_reinstall_ends_the_run_as_unfinished(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _bundled(tmp_path, monkeypatch, 0o777)

    step = repair_engine.repair_native_install(dry_run=False)
    report = repair_engine.build_report([step], dry_run=False)

    # Nothing failed and nothing here can fix it, so the run must neither
    # report a healthy install nor tell the user to run repair again.
    assert step["status"] == "skipped"
    assert step["needs_attention"] == ["native runtime"]
    assert report["status"] == "partial"
    assert "still need attention" in str(report["summary"])
    assert "Re-run" not in str(report["summary"])


def test_a_source_install_with_no_runtime_does_not_make_the_run_unfinished(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / "hol-guard-runtime"
    monkeypatch.setattr(native_runtime, "_bundled_runtime_candidate", lambda: missing)
    monkeypatch.setattr(native_runtime, "_runtime_candidates", lambda: (missing,))

    step = repair_engine.repair_native_install(dry_run=False)
    report = repair_engine.build_report([step], dry_run=False)

    assert step["status"] == "skipped"
    assert "needs_attention" not in step or step["needs_attention"] == []
    assert report["status"] == "healthy"


def test_a_refused_bit_does_not_send_the_user_back_to_repair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _bundled(tmp_path, monkeypatch, 0o644)
    monkeypatch.setattr(native_runtime, "_trusted_owner_and_mode", lambda metadata, path: False)

    step = repair_engine.repair_native_install(dry_run=False)
    report = repair_engine.build_report([step], dry_run=False)

    # A refusal comes from the filesystem or from who owns the file, and the
    # next run meets the same answer. Reporting it as a failed step would close
    # the run by telling the user to run repair again, which is a circle.
    assert step["outcome"] == "refused"
    assert step["status"] == "skipped"
    assert step["needs_attention"] == ["native runtime"]
    assert report["status"] == "partial"
    assert "without `sudo`" in str(step["action"])
    assert "Re-run" not in str(report["summary"])


def test_a_broken_override_does_not_condemn_a_working_bundled_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundled = _bundled(tmp_path, monkeypatch, 0o755)
    override = tmp_path / "override"
    override.mkdir()
    pointed_at = override / "hol-guard-runtime"
    pointed_at.write_bytes(b"#!/bin/sh\nexit 0\n")
    pointed_at.chmod(0o777)
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(pointed_at))
    # Selection walks these in order and takes the first it accepts, so the
    # world-writable override is skipped and the bundled copy is what runs.
    monkeypatch.setattr(native_runtime, "_runtime_candidates", lambda: (pointed_at, bundled))

    report = repair_native_runtime_install(dry_run=False)
    step = repair_engine.repair_native_install(dry_run=False)

    assert report["outcome"] == "healthy"
    assert {row["slot"]: row["state"] for row in report["candidates"]} == {
        "override": "untrusted_owner_or_mode",
        "bundled": "present",
    }
    # The fault beside it is still reported; it is just not a reason to tell
    # the user their install needs replacing.
    assert step["status"] == "ok"
