from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.adapters.diagnostic_probes import without_command_probes
from codex_plugin_scanner.guard.cli import doctor_native_runtime
from codex_plugin_scanner.guard.cli.doctor_native_runtime import NativeAvailabilityResult, doctor_native_availability
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity, NativeRuntimeStatus


@pytest.mark.parametrize(("runtime_sha256", "available"), [("b" * 64, True), (None, False)])
def test_passive_scope_answers_availability_without_probing_or_repairing(
    monkeypatch: pytest.MonkeyPatch, runtime_sha256: str | None, available: bool
) -> None:
    def unexpected_probe() -> NativeRuntimeStatus:
        pytest.fail("Passive diagnostics must not probe or change the native binary")

    monkeypatch.setattr(native_runtime, "native_runtime_status", unexpected_probe)
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: runtime_sha256)
    monkeypatch.setattr(native_runtime, "native_mode", lambda: "auto")

    with without_command_probes():
        result = doctor_native_availability()

    assert result["mode"] == "auto"
    assert result["available"] is available
    assert result["compatible"] is None
    assert result["reason_code"] == "native_status_probe_skipped"
    assert result["evaluation_verified"] is False
    # The shared-install panel is for a busy owner only; nothing to say here.
    assert "message" not in result


@pytest.mark.parametrize(
    ("available", "compatible", "reason"),
    [
        (False, False, "native_binary_missing"),
        (True, False, "native_manifest_version_mismatch"),
        (True, True, "native_available"),
    ],
)
def test_availability_preserves_validation_result_without_claiming_evaluation(
    monkeypatch: pytest.MonkeyPatch, available: bool, compatible: bool, reason: str
) -> None:
    status = NativeRuntimeStatus(mode="auto", available=available, compatible=compatible, reason=reason)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    assert doctor_native_availability() == {
        "mode": "auto",
        "available": available,
        "compatible": compatible,
        "reason_code": reason,
        "evaluation_verified": False,
    }


def test_availability_does_not_serialize_binary_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    identity = NativeRuntimeIdentity(path=Path("/private/user/native-secret"), size=123, mtime_ns=456, sha256="a" * 64)
    status = NativeRuntimeStatus(
        mode="auto", available=True, compatible=True, reason="native_available", identity=identity
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    encoded = json.dumps(doctor_native_availability())
    assert "private" not in encoded
    assert "sha256" not in encoded
    assert "mtime" not in encoded


@pytest.mark.parametrize("exception", [OSError, RuntimeError, ValueError])
def test_failed_probe_does_not_disclose_exception(monkeypatch: pytest.MonkeyPatch, exception: type[Exception]) -> None:
    def failed_probe() -> NativeRuntimeStatus:
        raise exception("/private/user/native-secret")

    monkeypatch.setattr(native_runtime, "native_runtime_status", failed_probe)
    result = doctor_native_availability()
    assert result["reason_code"] == "native_status_probe_failed"
    assert result["mode"] == "unknown"
    assert result["available"] is False
    assert result["evaluation_verified"] is False
    assert "private" not in json.dumps(result)


def test_invalid_reason_is_not_disclosed(monkeypatch: pytest.MonkeyPatch) -> None:
    status = NativeRuntimeStatus(mode="auto", available=False, compatible=False, reason="/private/user/native-secret")
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    assert doctor_native_availability()["reason_code"] == "native_status_reason_unavailable"


def _hold_owner_lock(state_base: Path):
    fcntl = pytest.importorskip("fcntl")
    state_base.mkdir(parents=True)
    handle = (state_base / "managed-resident-owner.v1.lock").open("w+b")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    return handle


def _status_for(runtime_sha256: str) -> NativeRuntimeStatus:
    identity = NativeRuntimeIdentity(path=Path("hol-guard-runtime"), size=1, mtime_ns=1, sha256=runtime_sha256)
    return NativeRuntimeStatus(mode="auto", available=True, compatible=True, reason="native_ready", identity=identity)


def _availability_while_held(
    guard_home: Path, runtime_sha256: str, monkeypatch: pytest.MonkeyPatch
) -> NativeAvailabilityResult:
    # flock conflicts across separate open() calls, even inside one process.
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: _status_for(runtime_sha256))
    return doctor_native_availability(guard_home)


def test_a_resident_owned_by_another_install_is_explained(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with _hold_owner_lock(tmp_path / "native-runtime"):
        result = _availability_while_held(tmp_path, "a" * 64, monkeypatch)

    assert result["reason_code"] == "native_resident_owner_busy"
    assert "Another Guard install" in result["message"]


def test_a_live_resident_of_this_runtime_is_not_called_another_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_base = tmp_path / "native-runtime"
    with _hold_owner_lock(state_base):
        resident = state_base / "resident-v3-aaaaaaaaaaaaaaaa"
        resident.mkdir()
        state = {"runtime_sha256": "a" * 64, "process_id": os.getpid()}
        (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")
        result = _availability_while_held(tmp_path, "a" * 64, monkeypatch)

    assert result["reason_code"] == "native_ready"
    assert "message" not in result


def test_a_free_owner_lock_is_not_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: _status_for("a" * 64))

    result = doctor_native_availability(tmp_path)

    assert result["reason_code"] == "native_ready"
    assert "message" not in result


def test_the_default_doctor_explains_a_busy_owner_without_running_the_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.adapters.diagnostic_probes import without_command_probes
    from codex_plugin_scanner.guard.cli import doctor_native_runtime

    def _must_not_run() -> NativeRuntimeStatus:
        raise AssertionError("the runtime must not run while command probes are off")

    monkeypatch.setattr(native_runtime, "native_runtime_status", _must_not_run)
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: "a" * 64)
    with _hold_owner_lock(tmp_path / "native-runtime"), without_command_probes():
        result = doctor_native_availability(tmp_path)

    assert result["reason_code"] == "native_resident_owner_busy"
    # The binary validated without being run, so availability is a real answer.
    assert result["available"] is True
    assert "Another Guard install" in result["message"]


def test_resident_presence_sees_a_live_resident_for_this_runtime(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    resident = tmp_path / "native-runtime" / "resident-v3-aaaaaaaaaaaaaaaa"
    resident.mkdir(parents=True)
    state = {"runtime_sha256": "a" * 64, "process_id": os.getpid()}
    (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")

    assert native_resident_presence(tmp_path, "a" * 64) == {
        "live": True,
        "owner_lock_held": False,
        "generations": 1,
    }


def test_resident_presence_ignores_another_runtime_build(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    resident = tmp_path / "native-runtime" / "resident-v3-bbbbbbbbbbbbbbbb"
    resident.mkdir(parents=True)
    state = {"runtime_sha256": "b" * 64, "process_id": os.getpid()}
    (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")

    presence = native_resident_presence(tmp_path, "a" * 64)

    assert presence["live"] is False
    assert presence["generations"] == 0


def test_resident_presence_reports_a_held_owner_lock(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    with _hold_owner_lock(tmp_path / "native-runtime"):
        presence = native_resident_presence(tmp_path, "a" * 64)

    assert presence["owner_lock_held"] is True
    assert presence["live"] is False


def test_resident_presence_is_unknown_without_a_runtime_identity(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    assert native_resident_presence(tmp_path, None) == {
        "live": None,
        "owner_lock_held": None,
        "generations": 0,
    }


def test_resident_presence_survives_a_damaged_state_file(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    resident = tmp_path / "native-runtime" / "resident-v3-aaaaaaaaaaaaaaaa"
    resident.mkdir(parents=True)
    (resident / "generation-1.json").write_text("{not json", encoding="utf-8")
    (resident / "generation-2.json").write_text("[]", encoding="utf-8")

    presence = native_resident_presence(tmp_path, "a" * 64)

    assert presence["live"] is False
    assert presence["generations"] == 0


def test_the_section_carries_availability_resident_and_this_process_counters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.cli import doctor_native_runtime

    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: _status_for("a" * 64))
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: "a" * 64)

    section = doctor_native_runtime.native_runtime_section(tmp_path)

    assert section["availability"]["reason_code"] == "native_ready"
    assert section["resident"] == {"live": False, "owner_lock_held": False, "generations": 0}
    assert isinstance(section["daemon_http"], dict)
    assert "repair" not in section


def test_the_section_does_not_serialize_the_binary_path_or_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.cli import doctor_native_runtime

    identity = NativeRuntimeIdentity(path=Path("/private/user/native-secret"), size=1, mtime_ns=1, sha256="c" * 64)
    status = NativeRuntimeStatus(mode="auto", available=True, compatible=True, reason="native_ready", identity=identity)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: "c" * 64)

    encoded = json.dumps(doctor_native_runtime.native_runtime_section(tmp_path))

    assert "native-secret" not in encoded
    assert "c" * 64 not in encoded
    assert "sha256" not in encoded
    assert "mtime" not in encoded


@pytest.mark.parametrize("process_id", [0, -1, True, "4", None])
def test_resident_presence_treats_a_state_file_without_a_real_pid_as_dead(tmp_path: Path, process_id: object) -> None:
    """A zero, negative, boolean or non-numeric pid names no process."""

    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    resident = tmp_path / "native-runtime" / "resident-v3-aaaaaaaaaaaaaaaa"
    resident.mkdir(parents=True)
    state = {"runtime_sha256": "a" * 64, "process_id": process_id}
    (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")

    presence = native_resident_presence(tmp_path, "a" * 64)

    # The generation is still counted; only its liveness claim is rejected.
    assert presence == {"live": False, "owner_lock_held": False, "generations": 1}


def test_resident_presence_rejects_a_reused_pid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A live pid counts only while it is still the process the state named."""

    from codex_plugin_scanner.guard import native_resident_watchdog
    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    resident = tmp_path / "native-runtime" / "resident-v3-aaaaaaaaaaaaaaaa"
    resident.mkdir(parents=True)
    state = {
        "runtime_sha256": "a" * 64,
        "process_id": os.getpid(),
        "process_start_marker": "linux:111",
    }
    (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setattr(native_resident_watchdog, "process_start_token", lambda pid: "linux:222")

    presence = native_resident_presence(tmp_path, "a" * 64)

    assert presence["live"] is False
    assert presence["generations"] == 1


def test_resident_presence_keeps_a_pid_that_still_matches_its_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import native_resident_watchdog
    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    resident = tmp_path / "native-runtime" / "resident-v3-aaaaaaaaaaaaaaaa"
    resident.mkdir(parents=True)
    marker = "linux:111"
    state = {"runtime_sha256": "a" * 64, "process_id": os.getpid(), "process_start_marker": marker}
    (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setattr(native_resident_watchdog, "process_start_token", lambda pid: marker)

    assert native_resident_presence(tmp_path, "a" * 64)["live"] is True


def test_a_busy_owner_is_not_claimed_when_a_reused_pid_is_the_only_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both resident scans apply one rule, so they cannot disagree about liveness."""

    from codex_plugin_scanner.guard import native_resident_watchdog
    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    state_base = tmp_path / "native-runtime"
    monkeypatch.setattr(native_resident_watchdog, "process_start_token", lambda pid: "linux:222")
    with _hold_owner_lock(state_base):
        resident = state_base / "resident-v3-aaaaaaaaaaaaaaaa"
        resident.mkdir()
        state = {
            "runtime_sha256": "a" * 64,
            "process_id": os.getpid(),
            "process_start_marker": "linux:111",
        }
        (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")
        result = _availability_while_held(tmp_path, "a" * 64, monkeypatch)
        presence = native_resident_presence(tmp_path, "a" * 64)

    assert result["reason_code"] == "native_resident_owner_busy"
    assert presence["live"] is False


def _plant_budget(guard_home: Path, runtime_sha256: str, **fields: object) -> Path:
    scope = guard_home / "native-runtime" / f"resident-v3-{runtime_sha256[:16]}"
    scope.mkdir(parents=True, exist_ok=True)
    budget: dict[str, object] = {
        "schema": "hol-guard-resident-restart-budget.v1",
        "window_start_ms": int(time.time() * 1000),
        "attempts": 3,
        "circuit_until_ms": 0,
        "backoff_steps": 1,
    }
    budget.update(fields)
    path = scope / "restart-budget.json"
    path.write_text(json.dumps(budget), encoding="utf-8")
    return path


def _section_with_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    from codex_plugin_scanner.guard.cli import doctor_native_runtime

    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: _status_for("a" * 64))
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: "a" * 64)
    return doctor_native_runtime.native_runtime_section(tmp_path)


def test_a_paused_restart_budget_is_reported_as_a_fault_on_a_healthy_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The install is perfect and nothing can start, which is exactly the case a file scan misses."""

    _plant_budget(tmp_path, "a" * 64, circuit_until_ms=int(time.time() * 1000) + 5_000)

    section = _section_with_budget(tmp_path, monkeypatch)

    assert section["availability"]["available"] is True
    assert section["restart"]["paced"] is True
    assert section["restart"]["attempts"] == 3
    assert 0 < section["restart"]["retry_in_seconds"] <= 5
    assert "restarts of it are paused" in section["diagnosis"]["summary"]
    assert "hol-guard repair" in section["diagnosis"]["action"]


def test_a_budget_whose_pause_has_passed_reports_no_fault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _plant_budget(tmp_path, "a" * 64, circuit_until_ms=int(time.time() * 1000) - 5_000)

    section = _section_with_budget(tmp_path, monkeypatch)

    assert section["restart"] == {"paced": False, "attempts": 3, "retry_in_seconds": 0.0}
    assert "diagnosis" not in section


def test_a_home_that_never_restarted_a_resident_says_nothing_about_restarts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    section = _section_with_budget(tmp_path, monkeypatch)

    assert "restart" not in section
    assert "diagnosis" not in section


@pytest.mark.parametrize(
    "fields",
    [
        {"schema": "hol-guard-resident-restart-budget.v2"},
        {"attempts": True},
        {"attempts": -1},
        {"attempts": "3"},
        {"circuit_until_ms": "later"},
        {"circuit_until_ms": -1},
    ],
    ids=["schema", "boolean-attempts", "negative-attempts", "string-attempts", "string-pause", "negative-pause"],
)
def test_a_file_this_runtime_did_not_write_is_not_read_as_a_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fields: dict[str, object]
) -> None:
    """Reporting a pause from a damaged or forged file would be a fault nobody can clear."""

    _plant_budget(tmp_path, "a" * 64, **fields)

    assert "restart" not in _section_with_budget(tmp_path, monkeypatch)


def test_an_unreadable_budget_is_not_read_as_a_pause(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _plant_budget(tmp_path, "a" * 64)
    path.write_text("{ not json", encoding="utf-8")

    assert "restart" not in _section_with_budget(tmp_path, monkeypatch)


def test_a_pause_longer_than_the_runtime_ever_writes_is_reported_at_that_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Backoff tops out at 30s, so a file claiming a year is reported as the bound, not the year."""

    _plant_budget(tmp_path, "a" * 64, circuit_until_ms=int(time.time() * 1000) + 86_400_000)

    assert _section_with_budget(tmp_path, monkeypatch)["restart"]["retry_in_seconds"] == 30.0


def test_a_budget_for_another_runtime_build_is_not_this_runtime_s_pause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _plant_budget(tmp_path, "b" * 64, circuit_until_ms=int(time.time() * 1000) + 5_000)

    assert "restart" not in _section_with_budget(tmp_path, monkeypatch)


def test_the_restart_block_carries_no_path_or_runtime_hash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _plant_budget(tmp_path, "a" * 64, circuit_until_ms=int(time.time() * 1000) + 5_000)

    encoded = json.dumps(_section_with_budget(tmp_path, monkeypatch)["restart"])

    assert str(tmp_path) not in encoded
    assert "a" * 16 not in encoded


def test_attempts_from_a_closed_window_do_not_count_against_the_next_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The runtime clears the counter once its rolling window expires."""

    _plant_budget(tmp_path, "a" * 64, window_start_ms=int(time.time() * 1000) - 120_000)

    assert _section_with_budget(tmp_path, monkeypatch)["restart"] == {
        "paced": False,
        "attempts": 0,
        "retry_in_seconds": 0.0,
    }


@pytest.mark.parametrize(
    "fields",
    [
        {"attempts": 2**32},
        {"circuit_until_ms": 2**64},
        {"window_start_ms": 10**30},
        {"attempts": True},
        {"circuit_until_ms": "soon"},
        {"window_start_ms": None},
        {"attempts": -1},
    ],
    ids=[
        "attempts-past-u32",
        "deadline-past-u64",
        "window-past-u64",
        "attempts-boolean",
        "deadline-text",
        "window-missing",
        "attempts-negative",
    ],
)
def test_a_counter_the_runtime_could_not_have_written_is_not_read_as_a_pause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fields: dict[str, object]
) -> None:
    """A damaged or forged number is absence, not a report and never arithmetic."""

    _plant_budget(tmp_path, "a" * 64, **fields)

    assert "restart" not in _section_with_budget(tmp_path, monkeypatch)


def test_a_pause_running_beside_a_live_resident_is_not_diagnosed_as_a_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The runtime arms the next pause on the spawn it allows, so both are true at once."""

    from codex_plugin_scanner.guard import native_resident_watchdog

    resident = tmp_path / "native-runtime" / "resident-v3-aaaaaaaaaaaaaaaa"
    resident.mkdir(parents=True)
    marker = "linux:111"
    state = {"runtime_sha256": "a" * 64, "process_id": os.getpid(), "process_start_marker": marker}
    (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setattr(native_resident_watchdog, "process_start_token", lambda pid: marker)
    _plant_budget(tmp_path, "a" * 64, circuit_until_ms=int(time.time() * 1000) + 5_000)

    with without_command_probes():
        section = _section_with_budget(tmp_path, monkeypatch)

    assert section["resident"]["live"] is True
    assert section["restart"]["paced"] is True
    assert "diagnosis" not in section


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a platform with FIFOs")
def test_a_fifo_left_where_the_budget_belongs_never_blocks_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reader that blocks here would hang doctor on a writer that never comes."""

    scope = tmp_path / "native-runtime" / "resident-v3-aaaaaaaaaaaaaaaa"
    scope.mkdir(parents=True)
    os.mkfifo(scope / "restart-budget.json")

    assert "restart" not in _section_with_budget(tmp_path, monkeypatch)


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="needs a platform that refuses to follow links")
def test_a_symlink_left_where_the_budget_belongs_is_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Resident state is not a trust boundary a report may be redirected through."""

    elsewhere = _plant_budget(tmp_path, "b" * 64, circuit_until_ms=int(time.time() * 1000) + 5_000)
    scope = tmp_path / "native-runtime" / "resident-v3-aaaaaaaaaaaaaaaa"
    scope.mkdir(parents=True)
    (scope / "restart-budget.json").symlink_to(elsewhere)

    assert "restart" not in _section_with_budget(tmp_path, monkeypatch)


def test_the_budget_contract_this_report_mirrors_matches_the_runtime_s_own() -> None:
    """The runtime owns this file's shape; a report that reads it must not drift.

    Doctor reads the budget rather than asking the runtime for it because the
    pause exists precisely when the runtime will not start. That leaves the
    schema string, the rolling window and the backoff bound mirrored in Python,
    so this pins each one to the Rust constant it copies.
    """

    source = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/src/resident_restart_budget.rs"
    rust = source.read_text(encoding="utf-8")

    for constant, mirrored in (
        ("RESTART_WINDOW_MS: u64", doctor_native_runtime._RESTART_WINDOW_MS),
        ("RESTART_BACKOFF_MAX_MS: u64", int(doctor_native_runtime._MAX_RETRY_SECONDS * 1000)),
    ):
        match = re.search(rf"const {re.escape(constant)} = ([0-9_]+);", rust)
        assert match is not None, f"{constant} is no longer declared the way this test reads it"
        assert int(match.group(1).replace("_", "")) == mirrored, f"{constant} moved away from its Python mirror"

    schema = re.search(r'const BUDGET_SCHEMA: &str = "([^"]+)";', rust)
    assert schema is not None, "BUDGET_SCHEMA is no longer declared the way this test reads it"
    assert schema.group(1) == doctor_native_runtime._RESTART_BUDGET_SCHEMA
