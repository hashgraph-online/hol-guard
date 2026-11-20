from __future__ import annotations

import argparse
import io
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_recovery_store as diagnostics
from codex_plugin_scanner.guard.cli import commands_daemon_recovery as cli
from codex_plugin_scanner.guard.cli import commands_dispatch_cloud as router
from codex_plugin_scanner.guard.cli import commands_support_service as service
from codex_plugin_scanner.guard.native_command_control_authority_io import write_private_state
from codex_plugin_scanner.guard.native_recovery_store import (
    DIAGNOSTICS_STATE_NAME,
    MAX_DIAGNOSTICS_BYTES,
    RecoveryContractError,
    build_recovery_diagnostics,
    load_recovery_diagnostics,
    persist_recovery_snapshot,
    recovery_diagnostics_for_operation,
    validate_event_sequence,
    validate_recovery_snapshot,
)

FIXTURES = Path(__file__).parent / "fixtures" / "daemon_recovery_v1"
FIXED_DIAGNOSTICS_NOW = datetime(2026, 9, 23, tzinfo=timezone.utc)


@pytest.fixture
def fixed_diagnostics_clock(monkeypatch: pytest.MonkeyPatch) -> datetime:
    monkeypatch.setattr(diagnostics, "_retention_now", lambda _value=None: FIXED_DIAGNOSTICS_NOW)
    return FIXED_DIAGNOSTICS_NOW


def _snapshot(name: str = "valid_timeout.json") -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_malformed_archive_is_optional_at_cli_boundary(tmp_path: Path) -> None:
    snapshot = _snapshot()
    operation_id = uuid.UUID(str(snapshot["operationId"]))
    persist_recovery_snapshot(tmp_path, snapshot)
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


def test_diagnostics_dispatch_uses_caller_output_stream(tmp_path: Path) -> None:
    snapshot = _snapshot()
    persist_recovery_snapshot(tmp_path, snapshot)
    output = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="diagnostics", operation_id=snapshot["operationId"]),
        guard_home=tmp_path,
        home_dir=None,
        stdout=output,
    )

    assert result == 0
    assert output.getvalue().startswith("{")


def test_router_passes_recovery_stdout_and_stderr_to_dispatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
    persist_recovery_snapshot(tmp_path, snapshot)

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
def test_malformed_enum_values_are_classified_contract_errors_before_membership(field: str, value: object) -> None:
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
