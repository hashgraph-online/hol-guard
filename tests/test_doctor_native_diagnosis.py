"""A native runtime that is not ready has to say what is wrong and what fixes it."""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.adapters.diagnostic_probes import without_command_probes
from codex_plugin_scanner.guard.cli import doctor_native_diagnosis as diagnosis_module
from codex_plugin_scanner.guard.cli.doctor_native_diagnosis import (
    native_runtime_candidates,
    native_runtime_diagnosis,
    native_runtime_message,
)
from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_runtime_section
from codex_plugin_scanner.guard.cli.runtime_posture_command import render_runtime_status

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and execute bits")


def _plant(root: Path, name: str, mode: int) -> Path:
    target = root / name
    target.write_bytes(b"#!/bin/sh\nexit 0\n")
    target.chmod(mode)
    return target


def _candidates(monkeypatch: pytest.MonkeyPatch, *paths: Path) -> None:
    monkeypatch.setattr(native_runtime, "_runtime_candidates", lambda: tuple(paths))


def test_an_install_with_no_runtime_says_so_instead_of_naming_a_skipped_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _candidates(monkeypatch, tmp_path / "missing")

    # The reason code the passive callers report describes the probe they did
    # not run, so it cannot be what explains an install with nothing to probe.
    result = native_runtime_diagnosis("native_status_probe_skipped", available=False)

    assert result is not None
    assert "no native runtime binary" in result["summary"]
    assert "uv tool install --force hol-guard" in result["action"]
    assert result["candidates"] == [{"slot": "distribution", "state": "absent"}]


def test_a_runtime_another_account_can_write_is_named_as_a_trust_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _candidates(monkeypatch, _plant(tmp_path, "shared", 0o777))

    result = native_runtime_diagnosis("native_status_probe_skipped", available=False)

    assert result is not None
    assert "writable" in result["summary"]
    # The repair is the opposite of the reflex: installing as root is what puts
    # a Guard install in this state in the first place.
    assert "without `sudo`" in result["action"]
    assert result["candidates"] == [{"slot": "distribution", "state": "untrusted_owner_or_mode"}]


def test_a_runtime_that_validates_but_cannot_launch_is_still_diagnosed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _candidates(monkeypatch, _plant(tmp_path, "hol-guard-runtime", 0o644))

    # Identity validation never tests the execute bit, so the passive answer
    # calls this install available and it then fails at every hook. No reason
    # code describes it; only the files do, which is why the diagnosis reads
    # them.
    result = native_runtime_diagnosis("native_status_probe_skipped", available=True)

    assert result is not None
    assert "no execute permission" in result["summary"]
    assert "noexec" in result["action"]


def test_a_runtime_that_answered_is_not_blamed_on_a_candidate_it_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _candidates(monkeypatch, _plant(tmp_path, "noexec", 0o644), _plant(tmp_path, "hol-guard-runtime", 0o755))

    # ``native_ready`` comes back only after a candidate launched and answered,
    # so an earlier one missing its execute bit is one the probe stepped over.
    # Reporting it would tell a working install to repair a file nothing uses.
    assert native_runtime_diagnosis("native_ready", available=True) is None


def test_a_probe_that_failed_says_so_instead_of_blaming_the_installed_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _candidates(monkeypatch, _plant(tmp_path, "hol-guard-runtime", 0o755))

    # The check itself raised, so ``available`` is false while the files are
    # fine. Answering from the files alone would prescribe a reinstall for a
    # runtime that was never asked anything.
    result = native_runtime_diagnosis("native_status_probe_failed", available=False)

    assert result is not None
    assert "the check itself failed" in result["summary"]
    assert "doctor --native" in result["action"]
    assert result["candidates"] == [{"slot": "distribution", "state": "present"}]


def test_a_shared_resident_is_not_handed_execute_bit_advice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _candidates(monkeypatch, _plant(tmp_path, "hol-guard-runtime", 0o644))

    # Another install owns the resident, so nothing here needs repairing. A
    # missing execute bit on this copy must not turn that into a repair
    # instruction that contradicts the sentence above it.
    result = native_runtime_diagnosis("native_resident_owner_busy", available=True)

    assert result is not None
    assert "Another Guard install" in result["summary"]
    assert "No action is needed" in result["action"]


def test_a_healthy_runtime_is_not_diagnosed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _candidates(monkeypatch, _plant(tmp_path, "hol-guard-runtime", 0o755))

    assert native_runtime_diagnosis("native_ready", available=True) is None
    assert native_runtime_diagnosis("native_status_probe_skipped", available=True) is None


def test_the_candidate_the_passive_answer_measured_decides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    refused = _plant(tmp_path, "shared", 0o777)
    usable = _plant(tmp_path, "hol-guard-runtime", 0o755)
    _candidates(monkeypatch, refused, usable)

    # Validation skips the candidates it refuses, so one it would never reach
    # must not be reported as the reason this install is broken.
    assert native_runtime_diagnosis("native_status_probe_skipped", available=True) is None

    _candidates(monkeypatch, refused, _plant(tmp_path, "noexec", 0o644), usable)
    result = native_runtime_diagnosis("native_status_probe_skipped", available=True)
    assert result is not None and "no execute permission" in result["summary"]


def test_a_symlink_where_the_runtime_belongs_is_reported_as_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = tmp_path / "link"
    link.symlink_to(_plant(tmp_path, "hol-guard-runtime", 0o755))
    _candidates(monkeypatch, link)

    result = native_runtime_diagnosis("native_status_probe_skipped", available=False)

    assert result is not None
    assert result["candidates"] == [{"slot": "distribution", "state": "not_a_regular_file"}]


def test_a_slot_is_a_role_so_no_path_reaches_the_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _plant(tmp_path, "hol-guard-runtime", 0o755)
    override = _plant(tmp_path, "override", 0o755)
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(override))
    _candidates(monkeypatch, override, native_runtime._bundled_runtime_candidate())

    rows = native_runtime_candidates()

    assert [row["slot"] for row in rows] == ["override", "bundled"]
    # A diagnosis is pasted into issues and support threads; a home directory
    # or an account name in it is a disclosure the reader cannot undo.
    assert str(tmp_path) not in repr(rows)


def test_every_reason_the_runtime_can_report_is_explained() -> None:
    source = Path(native_runtime.__file__).read_text(encoding="utf-8")
    reasons = {
        node.value.value
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.keyword)
        and node.arg == "reason"
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    manifest_reasons = {
        node.value
        for call in ast.walk(ast.parse(source))
        if isinstance(call, ast.Return) and isinstance(call.value, ast.Tuple)
        for node in call.value.elts
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith("native_")
    }

    # A new reason code with no entry here reaches a user as a bare identifier,
    # which is the whole failure this module exists to stop.
    assert reasons, "no reason literals were found; the parser needs updating, not the table"
    unexplained = {
        reason
        for reason in reasons | manifest_reasons
        # ``native_ready`` and an unavailable runtime are both answered elsewhere.
        if reason not in {"native_ready", "native_unavailable"} and reason not in diagnosis_module._DIAGNOSES
    }
    assert unexplained == set()


def test_the_section_carries_the_diagnosis_only_while_something_is_wrong(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _candidates(monkeypatch, tmp_path / "missing")
    with without_command_probes():
        broken = native_runtime_section(None)

    assert "diagnosis" in broken
    rendered = render_runtime_status(broken)
    assert "What to do:" in rendered
    assert "Runtime binary, by install slot: distribution absent." in rendered
    assert str(tmp_path) not in rendered

    _candidates(monkeypatch, _plant(tmp_path, "hol-guard-runtime", 0o755))
    with without_command_probes():
        healthy = native_runtime_section(None)

    assert "diagnosis" not in healthy


def test_a_busy_resident_owner_is_explained_once_not_twice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _candidates(monkeypatch, _plant(tmp_path, "hol-guard-runtime", 0o755))
    section = {
        "availability": {
            "mode": "auto",
            "available": True,
            "compatible": None,
            "reason_code": "native_resident_owner_busy",
            "message": native_runtime_message("native_resident_owner_busy"),
        },
        "diagnosis": native_runtime_diagnosis("native_resident_owner_busy", available=True),
    }

    rendered = render_runtime_status(section)

    assert rendered.count("Another Guard install") == 1
    # Nothing is broken here, so the action says that rather than inventing a repair.
    assert "No action is needed" in rendered


def test_an_unreadable_candidate_is_not_mistaken_for_an_absent_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _plant(tmp_path, "hol-guard-runtime", 0o755)
    real_lstat = Path.lstat

    def refuse(self: Path) -> os.stat_result:
        # A directory the account cannot traverse raises PermissionError rather
        # than FileNotFoundError. Raising it here instead of removing the
        # directory's permission bits keeps the case decided by the code under
        # test rather than by whether this process can ignore those bits.
        if self == candidate:
            raise PermissionError(13, "Permission denied")
        return real_lstat(self)

    monkeypatch.setattr(Path, "lstat", refuse)
    _candidates(monkeypatch, candidate)

    # A reinstall is not the same repair as a chmod, so the two must not share
    # a state.
    assert native_runtime_candidates() == [{"slot": "distribution", "state": "unreadable"}]


def test_a_binary_this_account_cannot_read_is_not_called_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _plant(tmp_path, "hol-guard-runtime", 0o111)
    real_access = os.access

    def refuse(path: object, mode: int, **kwargs: object) -> bool:
        # Privileged accounts read a mode 0o111 file anyway; the state under
        # test is the one validation meets when the read is actually refused.
        if Path(str(path)) == candidate and mode == os.R_OK:
            return False
        return real_access(path, mode, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "access", refuse)
    _candidates(monkeypatch, candidate)

    # Identity validation hashes the bytes, so this candidate is refused before
    # anything launches. Calling it present would report a runtime that "did
    # not answer" when nothing ever asked it.
    assert native_runtime_candidates() == [{"slot": "distribution", "state": "unreadable"}]


def test_the_unavailable_table_answers_every_state_a_candidate_can_have() -> None:
    assert set(diagnosis_module._UNAVAILABLE) == set(diagnosis_module._UNAVAILABLE_ORDER)


def test_a_paused_restart_is_explained_when_the_installed_files_are_perfect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _candidates(monkeypatch, _plant(tmp_path, "hol-guard-runtime", 0o755))

    result = native_runtime_diagnosis("native_ready", available=True, restart_paced=True)

    assert result is not None
    assert "fail closed" in result["summary"]
    assert "hol-guard repair" in result["action"]


def test_the_install_fault_a_crash_loop_grew_out_of_outranks_the_pause_it_caused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reinstalling clears both; telling the reader to wait out a pause clears neither."""

    _candidates(monkeypatch, tmp_path / "missing")

    result = native_runtime_diagnosis("native_status_probe_skipped", available=False, restart_paced=True)

    assert result is not None
    assert "no native runtime binary" in result["summary"]


def test_a_reason_code_the_runtime_reports_for_itself_explains_the_pause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The budget is read passively, so the runtime's own refusal has to be explained too."""

    _candidates(monkeypatch, _plant(tmp_path, "hol-guard-runtime", 0o755))

    result = native_runtime_diagnosis("native_resident_restart_circuit_open", available=True)

    assert result is not None
    assert "hol-guard repair" in result["action"]


@pytest.mark.parametrize(
    ("restart", "expected"),
    [
        (
            {"paced": True, "attempts": 3, "retry_in_seconds": 12.4},
            "  Restarts on this account: paused (3 recorded in this window); the next one is allowed in 12.4s",
        ),
        (
            {"paced": False, "attempts": 1, "retry_in_seconds": 0.0},
            "  Restarts on this account: not paused (1 recorded in this window)",
        ),
    ],
    ids=["paused", "clean"],
)
def test_runtime_status_prints_what_the_shared_restart_budget_says(restart: dict[str, object], expected: str) -> None:
    section = {
        "availability": {
            "mode": "auto",
            "available": True,
            "compatible": True,
            "reason_code": "native_ready",
            "evaluation_verified": False,
        },
        "resident": {"live": False, "owner_lock_held": False, "generations": 0},
        "restart": restart,
    }

    assert expected in render_runtime_status(section).splitlines()


def test_runtime_status_says_nothing_about_restarts_when_no_budget_was_read() -> None:
    section = {
        "availability": {
            "mode": "auto",
            "available": True,
            "compatible": True,
            "reason_code": "native_ready",
            "evaluation_verified": False,
        },
        "resident": {"live": False, "owner_lock_held": False, "generations": 0},
    }

    assert "Restarts on this account" not in render_runtime_status(section)
