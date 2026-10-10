from __future__ import annotations

import argparse
import io
import json
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_daemon_recovery as cli
from codex_plugin_scanner.guard.cli import commands_dispatch_cloud as router
from codex_plugin_scanner.guard.cli import commands_support_service as service
from codex_plugin_scanner.guard.daemon import recovery_diagnostics as diagnostics
from codex_plugin_scanner.guard.daemon.recovery_diagnostics import (
    DIAGNOSTICS_ARCHIVE_SCHEMA,
    DIAGNOSTICS_STATE_NAME,
    MAX_DIAGNOSTICS_BYTES,
    RecoveryDiagnosticsError,
    build_recovery_diagnostics,
    load_recovery_diagnostics,
    recovery_diagnostics_for_operation,
)
from codex_plugin_scanner.guard.daemon.user_recovery_contract import (
    RecoveryContractError,
    validate_event_sequence,
    validate_recovery_snapshot,
)
from codex_plugin_scanner.guard.native_command_control_authority_io import write_private_state
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

FIXTURES = Path(__file__).parent / "fixtures" / "daemon_recovery_v1"
FIXED_DIAGNOSTICS_NOW = datetime(2026, 9, 23, tzinfo=timezone.utc)


@pytest.fixture
def fixed_diagnostics_clock(monkeypatch: pytest.MonkeyPatch) -> datetime:
    monkeypatch.setattr(diagnostics, "_retention_now", lambda _value=None: FIXED_DIAGNOSTICS_NOW)
    return FIXED_DIAGNOSTICS_NOW


def _snapshot(name: str = "valid_timeout.json") -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_optional_native_archive_integrity_does_not_abort_mandatory_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _snapshot()

    def fail_optional(*_args: object, **_kwargs: object) -> None:
        raise NativePolicySnapshotError("native_policy_snapshot_archive_invalid")

    monkeypatch.setattr(cli, "persist_recovery_diagnostics", fail_optional)

    cli._persist_snapshot(tmp_path, snapshot)

    assert cli._load_latest_snapshot(tmp_path) == snapshot


def test_required_operation_snapshot_failure_remains_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _snapshot()
    monkeypatch.setattr(cli, "_persist_receipt", lambda *_args, **_kwargs: None)

    def fail_required(_home: Path, name: str, *_args: object, **_kwargs: object) -> None:
        if name == cli._STATE_NAME:
            raise NativePolicySnapshotError("native_policy_snapshot_required_failed")

    monkeypatch.setattr(cli, "write_private_state", fail_required)
    with pytest.raises(NativePolicySnapshotError, match="required_failed"):
        cli._persist_snapshot(tmp_path, snapshot)


@pytest.mark.parametrize(
    "failure",
    [
        NativePolicySnapshotError("native_policy_snapshot_archive_invalid"),
        NativePolicySnapshotError("native_policy_snapshot_archive_permissions_invalid"),
        NativePolicySnapshotError("native_policy_snapshot_archive_too_large"),
        RecoveryDiagnosticsError("recovery_diagnostics_state_invalid"),
        OSError("archive unavailable"),
    ],
    ids=["native-integrity", "permissions", "oversize", "malformed-archive", "unreadable-storage"],
)
def test_diagnostics_lookup_returns_snapshot_fallback_for_optional_archive_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    snapshot = _snapshot()
    operation_id = uuid.UUID(str(snapshot["operationId"]))
    monkeypatch.setattr(cli, "recovery_diagnostics_for_operation", lambda *_args: (_ for _ in ()).throw(failure))
    monkeypatch.setattr(cli, "_load_snapshot", lambda *_args: snapshot)
    monkeypatch.setattr(cli, "persist_recovery_diagnostics", lambda *_args, **_kwargs: None)

    report = cli._load_diagnostics(tmp_path, operation_id)

    assert report["operationId"] == snapshot["operationId"]
    assert report["latest"] == snapshot
    assert "path" not in json.dumps(report)
    assert "archive unavailable" not in json.dumps(report)


def test_malformed_archive_is_optional_at_cli_boundary(tmp_path: Path) -> None:
    snapshot = _snapshot()
    operation_id = uuid.UUID(str(snapshot["operationId"]))
    cli._persist_snapshot(tmp_path, snapshot)
    write_private_state(tmp_path, DIAGNOSTICS_STATE_NAME, b"{malformed", MAX_DIAGNOSTICS_BYTES)

    output = io.StringIO()
    error = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="diagnostics", operation_id=str(operation_id)),
        guard_home=tmp_path,
        home_dir=None,
        stdout=output,
        stderr=error,
    )

    assert result == 0
    assert error.getvalue() == ""
    assert json.loads(output.getvalue())["operationId"] == str(operation_id)


def test_compaction_oserror_is_optional_at_cli_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fixed_diagnostics_clock: datetime,
) -> None:
    snapshot = _snapshot()
    operation_id = uuid.UUID(str(snapshot["operationId"]))
    cli._persist_snapshot(tmp_path, snapshot)

    stale_report = build_recovery_diagnostics(
        snapshot,
        generated_at=fixed_diagnostics_clock - timedelta(days=8),
    )
    stale_archive = json.dumps(
        {"schema": DIAGNOSTICS_ARCHIVE_SCHEMA, "reports": [stale_report]},
        separators=(",", ":"),
    ).encode("utf-8")
    write_private_state(tmp_path, DIAGNOSTICS_STATE_NAME, stale_archive, MAX_DIAGNOSTICS_BYTES)

    original_write = diagnostics.write_private_state
    compaction_attempted = False

    def fail_compaction(
        guard_home: Path, name: str, payload: bytes, maximum_bytes: int
    ) -> None:
        nonlocal compaction_attempted
        if name == DIAGNOSTICS_STATE_NAME:
            decoded = json.loads(payload)
            if decoded == {"schema": DIAGNOSTICS_ARCHIVE_SCHEMA, "reports": []}:
                compaction_attempted = True
                raise OSError("diagnostics compaction unavailable")
        original_write(guard_home, name, payload, maximum_bytes)

    monkeypatch.setattr(diagnostics, "write_private_state", fail_compaction)
    output = io.StringIO()
    error = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="diagnostics", operation_id=str(operation_id)),
        guard_home=tmp_path,
        home_dir=None,
        stdout=output,
        stderr=error,
    )

    assert result == 0
    assert error.getvalue() == ""
    report = json.loads(output.getvalue())
    assert compaction_attempted is True
    assert report["operationId"] == snapshot["operationId"]
    assert report["latest"] == snapshot
    assert report["eventCount"] == report["retainedEventCount"] == 1
    assert report["truncated"] is False


def test_diagnostics_writer_serializes_read_modify_write_transactions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fixed_diagnostics_clock: datetime
) -> None:
    first = _snapshot()
    first["operationId"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    second = _snapshot()
    second["operationId"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    generated = fixed_diagnostics_clock
    archive: dict[str, object] = {"reports": []}
    first_write_started = threading.Event()
    second_loaded = threading.Event()
    write_count = 0
    write_count_lock = threading.Lock()

    def fake_load(_home: Path) -> list[dict[str, object]]:
        with write_count_lock:
            loaded = json.loads(json.dumps(archive["reports"]))
        if not isinstance(loaded, list):
            raise AssertionError("invalid fake archive")
        if first_write_started.is_set():
            second_loaded.set()
        return loaded

    def fake_write(_home: Path, _name: str, payload: bytes, _maximum: int) -> None:
        nonlocal write_count
        with write_count_lock:
            write_count += 1
            current_write = write_count
        if current_write == 1:
            first_write_started.set()
            second_loaded.wait(timeout=0.2)
        decoded = json.loads(payload)
        with write_count_lock:
            archive["reports"] = decoded["reports"]

    monkeypatch.setattr(diagnostics, "_load_archive", fake_load)
    monkeypatch.setattr(diagnostics, "write_private_state", fake_write)
    errors: list[BaseException] = []

    def persist(snapshot: dict[str, object], offset: int) -> None:
        try:
            diagnostics.persist_recovery_diagnostics(tmp_path, snapshot, generated_at=generated.replace(second=offset))
        except BaseException as error:  # pragma: no cover - surfaced below
            errors.append(error)

    first_thread = threading.Thread(target=persist, args=(first, 1))
    first_thread.start()
    assert first_write_started.wait(timeout=1.0)
    second_thread = threading.Thread(target=persist, args=(second, 2))
    second_thread.start()
    first_thread.join(timeout=2.0)
    second_thread.join(timeout=2.0)

    assert errors == []
    reports = archive["reports"]
    assert isinstance(reports, list)
    assert {report["operationId"] for report in reports} == {
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    }


def test_diagnostics_writer_serializes_separate_processes(
    tmp_path: Path, fixed_diagnostics_clock: datetime
) -> None:
    home = tmp_path / "guard-home"
    home.mkdir()
    marker = tmp_path / "first-write-started"
    release = tmp_path / "release-first-write"
    first = _snapshot()
    first["operationId"] = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    second = _snapshot()
    second["operationId"] = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    process_clock = fixed_diagnostics_clock + timedelta(days=8)
    script = """
import json
import sys
import time
from datetime import datetime
from pathlib import Path

from codex_plugin_scanner.guard.daemon import recovery_diagnostics as diagnostics

home = Path(sys.argv[1])
snapshot = json.loads(sys.argv[2])
marker = Path(sys.argv[3])
release = Path(sys.argv[4])
process_clock = datetime.fromisoformat(sys.argv[6])
diagnostics._retention_now = lambda _value=None: process_clock
original_write = diagnostics.write_private_state

def delayed_write(guard_home, name, payload, maximum_bytes):
    if name == diagnostics.DIAGNOSTICS_STATE_NAME and not marker.exists():
        marker.write_text("started", encoding="utf-8")
        while not release.exists():
            time.sleep(0.01)
    return original_write(guard_home, name, payload, maximum_bytes)

diagnostics.write_private_state = delayed_write
diagnostics.persist_recovery_diagnostics(home, snapshot, generated_at=diagnostics.datetime.fromisoformat(sys.argv[5]))
"""
    command = [
        sys.executable,
        "-c",
        script,
        str(home),
        json.dumps(first),
        str(marker),
        str(release),
        process_clock.isoformat(),
        process_clock.isoformat(),
    ]
    first_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + 20.0
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert marker.exists()
    second_command = [
        sys.executable,
        "-c",
        script,
        str(home),
        json.dumps(second),
        str(marker),
        str(release),
        (process_clock + timedelta(minutes=1)).isoformat(),
        process_clock.isoformat(),
    ]
    second_process = subprocess.Popen(second_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.15)
    release.write_text("release", encoding="utf-8")
    first_result = first_process.communicate(timeout=10.0)
    second_result = second_process.communicate(timeout=10.0)
    assert first_process.returncode == 0, first_result[1]
    assert second_process.returncode == 0, second_result[1]

    archive = json.loads((home / "native-runtime" / DIAGNOSTICS_STATE_NAME).read_text(encoding="utf-8"))
    assert {report["operationId"] for report in archive["reports"]} == {
        first["operationId"],
        second["operationId"],
    }


def test_uppercase_operation_id_lookup_is_canonicalized(tmp_path: Path) -> None:
    snapshot = _snapshot()
    operation_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    snapshot["operationId"] = operation_id
    diagnostics.persist_recovery_diagnostics(tmp_path, snapshot)

    report = recovery_diagnostics_for_operation(tmp_path, operation_id.upper())

    assert report["operationId"] == operation_id


def test_uppercase_recovery_snapshot_is_persisted_with_canonical_id(tmp_path: Path) -> None:
    snapshot = _snapshot()
    operation_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    snapshot["operationId"] = operation_id.upper()

    saved = diagnostics.persist_recovery_diagnostics(tmp_path, snapshot)
    loaded = diagnostics.load_recovery_diagnostics(tmp_path)

    assert saved["operationId"] == operation_id
    assert loaded is not None
    latest = loaded["latest"]
    events = loaded["events"]
    assert isinstance(latest, dict)
    assert isinstance(events, list)
    assert loaded["operationId"] == operation_id
    assert latest["operationId"] == operation_id
    assert all(isinstance(event, dict) and event["operationId"] == operation_id for event in events)


@pytest.mark.parametrize("command", ["status", "diagnostics"])
def test_cli_accepts_legacy_snapshot_with_uppercase_operation_id(
    tmp_path: Path, command: str
) -> None:
    snapshot = _snapshot()
    operation_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    snapshot["operationId"] = operation_id.upper()
    write_private_state(
        tmp_path,
        cli._STATE_NAME,
        json.dumps(snapshot, separators=(",", ":")).encode("utf-8"),
        cli._MAX_STATE_BYTES,
    )

    output = io.StringIO()
    error = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command=command, operation_id=operation_id),
        guard_home=tmp_path,
        home_dir=None,
        stdout=output,
        stderr=error,
    )

    assert result == 0, error.getvalue()
    report = json.loads(output.getvalue())
    assert report["operationId"] == operation_id


def test_diagnostics_archive_orders_by_utc_instant_then_operation_id(
    tmp_path: Path, fixed_diagnostics_clock: datetime
) -> None:
    first = _snapshot()
    first["operationId"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    second = _snapshot()
    second["operationId"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    third = _snapshot()
    third["operationId"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    same_instant = fixed_diagnostics_clock.replace(hour=0, minute=0, second=0, microsecond=0)

    persist = diagnostics.persist_recovery_diagnostics
    persist(
        tmp_path,
        first,
        generated_at=same_instant.astimezone(timezone(timedelta(hours=1))),
    )
    persist(
        tmp_path,
        second,
        generated_at=same_instant,
    )
    assert load_recovery_diagnostics(tmp_path)["operationId"] == second["operationId"]  # type: ignore[index]

    persist(
        tmp_path,
        third,
        generated_at=same_instant + timedelta(minutes=30),
    )
    assert load_recovery_diagnostics(tmp_path)["operationId"] == third["operationId"]  # type: ignore[index]


def test_diagnostics_read_survives_optional_archive_compaction_oserror(
    tmp_path: Path,
    fixed_diagnostics_clock: datetime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stale = _snapshot()
    stale["operationId"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    current = _snapshot()
    current["operationId"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    reports = [
        build_recovery_diagnostics(
            stale,
            generated_at=fixed_diagnostics_clock - timedelta(days=365),
        ),
        build_recovery_diagnostics(
            current,
            generated_at=fixed_diagnostics_clock,
        ),
    ]
    write_private_state(
        tmp_path,
        DIAGNOSTICS_STATE_NAME,
        diagnostics._encode_archive(reports),
        MAX_DIAGNOSTICS_BYTES,
    )

    def fail_optional_compaction(*_args: object, **_kwargs: object) -> None:
        raise OSError("archive compaction unavailable")

    monkeypatch.setattr(diagnostics, "write_private_state", fail_optional_compaction)

    report = load_recovery_diagnostics(tmp_path)

    assert report is not None
    assert report["operationId"] == current["operationId"]


def test_diagnostics_dispatch_uses_caller_output_stream(tmp_path: Path) -> None:
    snapshot = _snapshot()
    cli._persist_snapshot(tmp_path, snapshot)
    output = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="diagnostics", operation_id=snapshot["operationId"]),
        guard_home=tmp_path,
        home_dir=None,
        stdout=output,
    )

    assert result == 0
    assert output.getvalue().startswith("{")


def test_router_passes_recovery_stdout_and_stderr_to_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = io.StringIO()
    error = io.StringIO()
    captured: dict[str, object] = {}

    def fake_dispatch(*_args: object, **kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(cli, "dispatch_daemon_recovery", fake_dispatch)
    service._dispatch_guard_daemon_command(
        argparse.Namespace(daemon_command="recovery", daemon_recovery_command="diagnostics"),
        guard_home=tmp_path,
        workspace=None,
        context=None,
        store=None,
        output_stream=output,
        error_stream=error,
    )

    assert captured["stdout"] is output
    assert captured["stderr"] is error


def test_router_handler_forwards_output_stream_to_daemon_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = io.StringIO()
    captured: dict[str, object] = {}

    def fake_dispatch(*_args: object, **kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(router, "_dispatch_guard_daemon_command", fake_dispatch)
    router._run_guard_daemon_command(
        argparse.Namespace(daemon_command="recovery"),
        guard_home=tmp_path,
        output_stream=output,
    )

    assert captured["output_stream"] is output


def test_diagnostics_dispatch_keeps_a_falsey_caller_output_stream(tmp_path: Path) -> None:
    snapshot = _snapshot()
    cli._persist_snapshot(tmp_path, snapshot)

    class FalseyStream(io.StringIO):
        def __bool__(self) -> bool:
            return False

    output = FalseyStream()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="diagnostics", operation_id=snapshot["operationId"]),
        guard_home=tmp_path,
        home_dir=None,
        stdout=output,
    )

    assert result == 0
    assert output.getvalue().startswith("{")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("capabilities", [[]]),
        ("phase", []),
        ("checks", [{"id": [], "result": "pass", "reasonCode": "healthy"}]),
    ],
    ids=["unhashable-capability", "unhashable-phase", "unhashable-check-id"],
)
def test_malformed_enum_values_are_classified_contract_errors_before_membership(
    field: str, value: object
) -> None:
    payload = _snapshot("valid_timeout.json")
    payload[field] = value

    with pytest.raises(RecoveryContractError):
        validate_recovery_snapshot(payload)


def test_null_operation_id_is_only_allowed_for_inspection() -> None:
    payload = _snapshot("valid_timeout.json")
    payload["operationId"] = None

    validate_recovery_snapshot(payload, allow_inspection=True)
    with pytest.raises(RecoveryContractError, match="operation_id_required"):
        validate_recovery_snapshot(payload, allow_inspection=False)


def test_event_sequence_requires_an_operation_id() -> None:
    payload = _snapshot("valid_timeout.json")
    payload["operationId"] = None

    with pytest.raises(RecoveryContractError, match="operation_id_required"):
        validate_event_sequence(None, payload)


def test_obsolete_guard_home_archive_path_is_not_used(tmp_path: Path) -> None:
    snapshot = _snapshot()
    operation_id = str(snapshot["operationId"])
    obsolete = tmp_path / DIAGNOSTICS_STATE_NAME
    obsolete.write_text(json.dumps(build_recovery_diagnostics(snapshot)), encoding="utf-8")

    with pytest.raises(KeyError):
        recovery_diagnostics_for_operation(tmp_path, operation_id)
