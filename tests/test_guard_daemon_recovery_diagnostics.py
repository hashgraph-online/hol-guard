from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_daemon_recovery as cli
from codex_plugin_scanner.guard.daemon import recovery_diagnostics as diagnostics_module
from codex_plugin_scanner.guard.daemon.recovery_diagnostics import (
    DIAGNOSTICS_ARCHIVE_SCHEMA,
    DIAGNOSTICS_STATE_NAME,
    MAX_DIAGNOSTICS_BYTES,
    RecoveryDiagnosticsError,
    build_recovery_diagnostics,
    encode_recovery_diagnostics,
    load_recovery_diagnostics,
    persist_recovery_diagnostics,
    recovery_diagnostics_for_operation,
)
from codex_plugin_scanner.guard.native_command_control_authority_io import write_private_state

FIXTURE = Path(__file__).parent / "fixtures" / "daemon_recovery_v1" / "diagnostics_privacy_source.json"


def _source() -> dict[str, object]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _freeze_retention_now(monkeypatch: pytest.MonkeyPatch) -> datetime:
    now = datetime(2026, 9, 23, tzinfo=timezone.utc)

    def retention_now(value: datetime | None = None) -> datetime:
        return now if value is None else value

    monkeypatch.setattr(diagnostics_module, "_retention_now", retention_now)
    return now


def _large_events(operation_id: str, *, start: datetime, count: int = 100) -> list[dict[str, object]]:
    source = _source()
    source["operationId"] = operation_id
    return [
        {
            **source,
            "sequence": sequence,
            "updatedAt": (start + timedelta(seconds=sequence)).isoformat(),
        }
        for sequence in range(1, count + 1)
    ]


def test_diagnostics_allowlist_drops_private_source_fields() -> None:
    report = build_recovery_diagnostics(_source())
    encoded = encode_recovery_diagnostics(report).decode("utf-8")

    assert report["schema"] == "hol-guard-recovery-diagnostics.v1"
    assert report["eventCount"] == 1
    for canary in (
        "private-token-canary",
        "private-password-canary",
        "123456",
        "private-signed-url",
        "/redacted/path",
        "hol-guard daemon recovery restart",
    ):
        assert canary not in encoded
    assert set(report) == {
        "schema",
        "generatedAt",
        "operationId",
        "eventCount",
        "retainedEventCount",
        "truncated",
        "latest",
        "events",
    }


def test_diagnostics_are_bounded_and_retain_latest_event() -> None:
    source = _source()
    events = []
    for sequence in range(1, 300):
        event = dict(source)
        event["sequence"] = sequence
        event["updatedAt"] = f"2026-09-20T00:00:{sequence % 60:02d}+00:00"
        events.append(event)

    report = build_recovery_diagnostics(events)
    payload = encode_recovery_diagnostics(report)

    assert len(payload) <= MAX_DIAGNOSTICS_BYTES
    assert report["truncated"] is True
    assert report["latest"]["sequence"] == 299  # type: ignore[index]
    assert report["events"][-1]["sequence"] == 299  # type: ignore[index]


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("schema", "unsupported", "recovery_diagnostics_schema_invalid"),
        ("eventCount", 0, "recovery_diagnostics_event_count_invalid"),
        ("truncated", True, "recovery_diagnostics_truncation_invalid"),
        ("events", [], "recovery_diagnostics_events_invalid"),
        ("latest", {"password": "malformed-secret"}, "recovery_diagnostics_snapshot_invalid"),
    ),
)
def test_encode_rejects_malformed_public_reports_without_leaking_fields(
    field: str, value: object, reason: str
) -> None:
    report = build_recovery_diagnostics(_source())
    report[field] = value

    with pytest.raises(RecoveryDiagnosticsError) as raised:
        encode_recovery_diagnostics(report)

    assert raised.value.args == (reason,)
    assert "malformed-secret" not in str(raised.value)


def test_build_rejects_malformed_public_event_streams_without_leaking_fields() -> None:
    source = _source()
    cases: tuple[tuple[object, str], ...] = (
        (None, "recovery_diagnostics_events_invalid"),
        ([], "recovery_diagnostics_events_empty"),
        (
            [source, {**source, "sequence": source["sequence"]}],
            "recovery_diagnostics_event_sequence_invalid",
        ),
        (
            [
                source,
                {
                    **source,
                    "sequence": 5,
                    "operationId": "22222222-2222-4222-8222-222222222222",
                    "password": "malformed-secret",
                },
            ],
            "recovery_diagnostics_event_sequence_invalid",
        ),
    )

    for snapshots, reason in cases:
        with pytest.raises(RecoveryDiagnosticsError) as raised:
            build_recovery_diagnostics(snapshots)
        assert raised.value.args == (reason,)
        assert "malformed-secret" not in str(raised.value)


def test_build_redacts_tuple_snapshot_fields_and_normalizes_naive_generation_time() -> None:
    source = _source()
    capabilities = ("diagnostics", "inspect", "restart", "status")
    source["capabilities"] = capabilities
    raw_checks = source["checks"]
    assert isinstance(raw_checks, list)
    source["checks"] = tuple(raw_checks)

    report = build_recovery_diagnostics(source, generated_at=datetime(2026, 9, 20))
    latest = report["latest"]
    assert isinstance(latest, dict)

    assert report["generatedAt"] == "2026-09-20T00:00:00+00:00"
    assert latest["capabilities"] == list(capabilities)
    assert isinstance(latest["capabilities"], list)
    assert "path" not in latest


def test_build_rejects_a_non_mapping_public_snapshot_without_leaking_it() -> None:
    with pytest.raises(RecoveryDiagnosticsError) as raised:
        build_recovery_diagnostics([None])

    assert raised.value.args == ("recovery_diagnostics_snapshot_invalid",)


@pytest.mark.parametrize("operation_id", (None, "malformed-operation-id-canary"))
def test_validate_rejects_invalid_report_operation_ids_without_leaking_them(operation_id: object) -> None:
    report = build_recovery_diagnostics(_source())
    report["operationId"] = operation_id

    with pytest.raises(RecoveryDiagnosticsError) as raised:
        diagnostics_module.validate_recovery_diagnostics(report)

    assert raised.value.args == ("recovery_diagnostics_operation_id_invalid",)
    assert str(operation_id) not in str(raised.value)


@pytest.mark.parametrize(
    "generated_at",
    ("", "not-a-timestamp", "2026-09-20T00:00:00"),
)
def test_validate_rejects_public_reports_with_invalid_timestamps(generated_at: str) -> None:
    report = build_recovery_diagnostics(_source())
    report["generatedAt"] = generated_at

    with pytest.raises(RecoveryDiagnosticsError) as raised:
        diagnostics_module.validate_recovery_diagnostics(report)

    assert raised.value.args == ("recovery_diagnostics_timestamp_invalid",)


def test_validate_rejects_noncanonical_report_operation_ids() -> None:
    source = _source()
    source["operationId"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    report = build_recovery_diagnostics(source)
    report["operationId"] = "{aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa}"

    with pytest.raises(RecoveryDiagnosticsError) as raised:
        diagnostics_module.validate_recovery_diagnostics(report)

    assert raised.value.args == ("recovery_diagnostics_operation_id_invalid",)


def test_validate_rejects_report_retention_count_above_event_count() -> None:
    report = build_recovery_diagnostics(_source())
    event_count = report["eventCount"]
    assert isinstance(event_count, int)
    report["retainedEventCount"] = event_count + 1

    with pytest.raises(RecoveryDiagnosticsError) as raised:
        diagnostics_module.validate_recovery_diagnostics(report)

    assert raised.value.args == ("recovery_diagnostics_retained_count_invalid",)


def test_validate_rejects_cross_operation_report_events_before_latest_export() -> None:
    report = build_recovery_diagnostics(_source())
    events = report["events"]
    assert isinstance(events, list)
    first_event = events[0]
    assert isinstance(first_event, dict)
    event = dict(first_event)
    event["operationId"] = "22222222-2222-4222-8222-222222222222"
    report["events"] = [event]
    report["latest"] = event

    with pytest.raises(RecoveryDiagnosticsError) as raised:
        diagnostics_module.validate_recovery_diagnostics(report)

    assert raised.value.args == ("recovery_diagnostics_operation_changed",)


def test_validate_rejects_a_latest_snapshot_that_differs_from_the_event_stream() -> None:
    report = build_recovery_diagnostics(_source())
    latest = report["latest"]
    assert isinstance(latest, dict)
    report["latest"] = {**latest, "sequence": 5}

    with pytest.raises(RecoveryDiagnosticsError) as raised:
        diagnostics_module.validate_recovery_diagnostics(report)

    assert raised.value.args == ("recovery_diagnostics_latest_invalid",)


def test_build_rejects_cross_operation_event_even_when_sequence_increases() -> None:
    first = _source()
    second = {
        **first,
        "operationId": "22222222-2222-4222-8222-222222222222",
        "sequence": first["sequence"] + 1,
    }

    with pytest.raises(RecoveryDiagnosticsError) as raised:
        build_recovery_diagnostics([first, second])

    assert raised.value.args == ("recovery_diagnostics_event_sequence_invalid",)


def test_encode_rejects_an_unbounded_public_report() -> None:
    latest = build_recovery_diagnostics(_source())["latest"]
    assert isinstance(latest, dict)
    events = [{**latest, "sequence": sequence} for sequence in range(1, 121)]
    report = {
        "schema": "hol-guard-recovery-diagnostics.v1",
        "generatedAt": "2026-09-20T00:00:00+00:00",
        "operationId": latest["operationId"],
        "eventCount": len(events),
        "retainedEventCount": len(events),
        "truncated": False,
        "latest": events[-1],
        "events": events,
    }

    with pytest.raises(RecoveryDiagnosticsError) as raised:
        encode_recovery_diagnostics(report)

    assert raised.value.args == ("recovery_diagnostics_too_large",)


def test_diagnostics_persist_owner_private_and_reload_atomically(tmp_path: Path) -> None:
    report = persist_recovery_diagnostics(tmp_path, _source())
    loaded = load_recovery_diagnostics(tmp_path)
    state_dir = tmp_path / "native-runtime"
    report_path = state_dir / DIAGNOSTICS_STATE_NAME

    assert loaded == report
    assert report_path.is_file()
    assert len(report_path.read_bytes()) <= MAX_DIAGNOSTICS_BYTES
    if os.name != "nt":
        assert stat.S_IMODE(state_dir.stat().st_mode) & 0o077 == 0
        assert stat.S_IMODE(report_path.stat().st_mode) & 0o077 == 0
        assert not list(state_dir.glob(f".{DIAGNOSTICS_STATE_NAME}.*.tmp"))


def test_diagnostics_retention_keeps_only_recent_newest_incidents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = _freeze_retention_now(monkeypatch)
    operation_ids: list[str] = []
    for index in range(22):
        source = _source()
        operation_id = f"00000000-0000-4000-8000-{index:012d}"
        source["operationId"] = operation_id
        operation_ids.append(operation_id)
        persist_recovery_diagnostics(tmp_path, source, generated_at=now - timedelta(hours=21 - index))

    with pytest.raises(KeyError):
        recovery_diagnostics_for_operation(tmp_path, operation_ids[0])
    assert recovery_diagnostics_for_operation(tmp_path, operation_ids[-1])["operationId"] == operation_ids[-1]

    stale = _source()
    stale_id = "99999999-9999-4999-8999-999999999999"
    stale["operationId"] = stale_id
    persist_recovery_diagnostics(tmp_path, stale, generated_at=now - timedelta(days=8))
    fresh = _source()
    fresh_id = "88888888-8888-4888-8888-888888888888"
    fresh["operationId"] = fresh_id
    persist_recovery_diagnostics(tmp_path, fresh, generated_at=now)
    with pytest.raises(KeyError):
        recovery_diagnostics_for_operation(tmp_path, stale_id)


def test_large_archive_retention_drops_oldest_report_when_archive_is_too_large(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = _freeze_retention_now(monkeypatch)
    first_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    second_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

    persist_recovery_diagnostics(tmp_path, _large_events(first_id, start=now), generated_at=now)
    persist_recovery_diagnostics(tmp_path, _large_events(second_id, start=now), generated_at=now)

    loaded = load_recovery_diagnostics(tmp_path)
    assert loaded is not None
    assert loaded["operationId"] == second_id
    with pytest.raises(KeyError):
        recovery_diagnostics_for_operation(tmp_path, first_id)

    archive = json.loads((tmp_path / "native-runtime" / DIAGNOSTICS_STATE_NAME).read_text(encoding="utf-8"))
    assert [report["operationId"] for report in archive["reports"]] == [second_id]


def test_pre_archive_report_decodes_through_public_loader(tmp_path: Path) -> None:
    report = build_recovery_diagnostics(_source())
    write_private_state(
        tmp_path,
        DIAGNOSTICS_STATE_NAME,
        json.dumps(report, separators=(",", ":")).encode("utf-8"),
        MAX_DIAGNOSTICS_BYTES,
    )

    assert load_recovery_diagnostics(tmp_path) == report


def test_stale_diagnostics_are_pruned_and_persisted_during_read_and_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = _freeze_retention_now(monkeypatch)
    stale_id = "99999999-9999-4999-8999-999999999999"
    stale = _source()
    stale["operationId"] = stale_id
    stale_report = build_recovery_diagnostics(stale, generated_at=now - timedelta(days=8))

    def write_archive() -> None:
        payload = json.dumps(
            {"schema": DIAGNOSTICS_ARCHIVE_SCHEMA, "reports": [stale_report]},
            separators=(",", ":"),
        ).encode("utf-8")
        write_private_state(tmp_path, DIAGNOSTICS_STATE_NAME, payload, MAX_DIAGNOSTICS_BYTES)

    write_archive()
    assert load_recovery_diagnostics(tmp_path) is None
    persisted = json.loads((tmp_path / "native-runtime" / DIAGNOSTICS_STATE_NAME).read_text(encoding="utf-8"))
    assert persisted == {"schema": DIAGNOSTICS_ARCHIVE_SCHEMA, "reports": []}

    write_archive()
    with pytest.raises(KeyError):
        recovery_diagnostics_for_operation(tmp_path, stale_id)
    persisted = json.loads((tmp_path / "native-runtime" / DIAGNOSTICS_STATE_NAME).read_text(encoding="utf-8"))
    assert persisted == {"schema": DIAGNOSTICS_ARCHIVE_SCHEMA, "reports": []}


def test_archive_decode_rejects_malformed_state_without_leaking_sensitive_values(tmp_path: Path) -> None:
    malformed = {
        "schema": DIAGNOSTICS_ARCHIVE_SCHEMA,
        "reports": [{"password": "archive-secret"}],
    }
    write_private_state(
        tmp_path,
        DIAGNOSTICS_STATE_NAME,
        json.dumps(malformed, separators=(",", ":")).encode("utf-8"),
        MAX_DIAGNOSTICS_BYTES,
    )

    with pytest.raises(RecoveryDiagnosticsError) as raised:
        load_recovery_diagnostics(tmp_path)

    assert raised.value.args == ("recovery_diagnostics_state_invalid",)
    assert "archive-secret" not in str(raised.value)


@pytest.mark.parametrize("payload", (b"{not-json", b"\xff"))
def test_archive_decode_rejects_invalid_serialized_state(tmp_path: Path, payload: bytes) -> None:
    write_private_state(tmp_path, DIAGNOSTICS_STATE_NAME, payload, MAX_DIAGNOSTICS_BYTES)

    with pytest.raises(RecoveryDiagnosticsError) as raised:
        load_recovery_diagnostics(tmp_path)

    assert raised.value.args == ("recovery_diagnostics_state_invalid",)


@pytest.mark.parametrize(
    "archive",
    (
        {"schema": DIAGNOSTICS_ARCHIVE_SCHEMA, "unexpected": []},
        {"schema": "unsupported", "reports": []},
        {"schema": DIAGNOSTICS_ARCHIVE_SCHEMA, "reports": {}},
    ),
)
def test_archive_loader_rejects_invalid_public_archive_shapes(tmp_path: Path, archive: dict[str, object]) -> None:
    write_private_state(
        tmp_path,
        DIAGNOSTICS_STATE_NAME,
        json.dumps(archive, separators=(",", ":")).encode("utf-8"),
        MAX_DIAGNOSTICS_BYTES,
    )

    with pytest.raises(RecoveryDiagnosticsError) as raised:
        load_recovery_diagnostics(tmp_path)

    assert raised.value.args == ("recovery_diagnostics_state_invalid",)


def test_stale_archive_read_remains_usable_when_optional_compaction_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = _freeze_retention_now(monkeypatch)
    stale_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    stale_report = build_recovery_diagnostics(
        _source(), generated_at=now - timedelta(days=8)
    )
    stale_report["operationId"] = stale_id
    stale_report["latest"] = {**stale_report["latest"], "operationId": stale_id}  # type: ignore[index]
    stale_report["events"] = [{**stale_report["events"][0], "operationId": stale_id}]  # type: ignore[index]
    write_private_state(
        tmp_path,
        DIAGNOSTICS_STATE_NAME,
        json.dumps({"schema": DIAGNOSTICS_ARCHIVE_SCHEMA, "reports": [stale_report]}, separators=(",", ":")).encode(
            "utf-8"
        ),
        MAX_DIAGNOSTICS_BYTES,
    )

    def unavailable_compaction(*_args: object, **_kwargs: object) -> None:
        raise OSError("archive_compaction_unavailable")

    monkeypatch.setattr(diagnostics_module, "write_private_state", unavailable_compaction)

    assert load_recovery_diagnostics(tmp_path) is None
    with pytest.raises(KeyError):
        recovery_diagnostics_for_operation(tmp_path, stale_id)
    persisted = (tmp_path / "native-runtime" / DIAGNOSTICS_STATE_NAME).read_text(encoding="utf-8")
    assert stale_id in persisted
    assert "archive_compaction_unavailable" not in persisted


def test_diagnostics_reject_sensitive_unknown_report_fields() -> None:
    report = build_recovery_diagnostics(_source())
    report["password"] = "private-password-canary"
    with pytest.raises(RecoveryDiagnosticsError, match="fields"):
        encode_recovery_diagnostics(report)


def test_cli_diagnostics_reads_private_report_without_running_recovery(tmp_path: Path) -> None:
    operation_id = str(_source()["operationId"])
    cli._persist_snapshot(tmp_path, build_recovery_diagnostics(_source())["latest"])
    output = __import__("io").StringIO()
    result = cli.dispatch_daemon_recovery(
        __import__("argparse").Namespace(daemon_recovery_command="diagnostics", operation_id=operation_id),
        guard_home=tmp_path,
        home_dir=None,
        stdout=output,
    )

    assert result == 0
    assert json.loads(output.getvalue())["operationId"] == operation_id
