"""The resident client for the hook evidence writer: wire shape and the two signals it consumes."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_evidence_writer
from codex_plugin_scanner.guard.native_hook_evidence_writer import (
    NativeHookEvidenceWriter,
    NativeHookEvidenceWriterUnavailableError,
)

# pyright: reportAny=false, reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false


# The signal shape the resident reports: a failure plus the identifier that
# clears it once this client has recovered from it.
_FATAL: dict[str, Any] = {"id": "fatal-1", "code": "native_guard_store_sqlite_corrupt"}


class _Identity:
    sha256 = "b" * 64


class _Status:
    identity = _Identity()


class _Store:
    """The parts of ``GuardStore`` the client holds: a home, a source, recovery."""

    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self.guard_source = "oauth"
        self.recovered: list[BaseException] = []

    def _recover_fatal_sqlite_store(self, error: BaseException, **_kwargs: Any) -> bool:
        self.recovered.append(error)
        return True


def _answer(payload: dict[str, Any], *, status: str = "ok", code: str = "ok") -> Any:
    """A resident reply bound to whatever request the client just sent."""

    sent: list[dict[str, Any]] = []

    def respond(*, request: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        sent.append(request)
        digest = "sha256:" + native_hook_evidence_writer._canonical_request_sha256(request)
        return {
            "schema": "guard-hook-evidence-writer-result.v1",
            "request_id": request["request_id"],
            "request_sha256": digest,
            "status": status,
            # A fresh copy each call: the client consumes the signals out of
            # the payload it is handed, and a shared dict would hide a second
            # report behind the first read.
            "code": code,
            "payload": dict(payload),
        }

    respond.sent = sent  # pyright: ignore[reportFunctionMemberAccess]
    return respond


def _resident_holding_a_fatal_store(payload: dict[str, Any]) -> Any:
    """A resident that keeps reporting its failure until the client names it.

    The acknowledgement a request carries is applied before the reply is
    built, so a failure recorded after it is still reported.
    """

    sent: list[dict[str, Any]] = []
    pending: list[dict[str, Any] | None] = [_FATAL]

    def respond(*, request: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        sent.append(request)
        if request.get("store_fatal_ack") == _FATAL["id"]:
            pending[0] = None
        body = dict(payload)
        body["store_fatal"] = pending[0]
        return {
            "schema": "guard-hook-evidence-writer-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + native_hook_evidence_writer._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": body,
        }

    respond.sent = sent  # pyright: ignore[reportFunctionMemberAccess]
    return respond


@pytest.fixture
def writer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> NativeHookEvidenceWriter:
    monkeypatch.setattr(native_hook_evidence_writer, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_hook_evidence_writer, "native_runtime_status", lambda: _Status())
    monkeypatch.setattr(native_hook_evidence_writer, "native_record_resident_success", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(native_hook_evidence_writer, "native_record_resident_failure", lambda *_args, **_kwargs: None)
    return NativeHookEvidenceWriter(store=_Store(tmp_path / "guard-home"))


def _install(monkeypatch: pytest.MonkeyPatch, respond: Any) -> None:
    monkeypatch.setattr(native_hook_evidence_writer, "_resident_request", respond)


def test_a_command_activity_submission_sends_the_flat_writer_request(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    respond = _answer({"queued": True})
    _install(monkeypatch, respond)

    queued = writer.submit_command_activity(
        harness="claude-code",
        event="PreToolUse",
        payload={"tool_name": "Bash"},
        succeeded=True,
        policy_action="allow",
    )

    assert queued is True
    request = respond.sent[0]
    assert request["schema"] == "guard-hook-evidence-writer-request.v1"
    assert request["action"] == "submit_command_activity"
    assert request["guard_home"] == str(writer.guard_home)
    assert request["harness"] == "claude-code"
    assert request["payload"] == {"tool_name": "Bash"}
    assert request["approval_reuse_status"] == "not-applicable"
    # Always on the wire: the resident digests the request it decoded, and a
    # key sent only sometimes would make the two digests disagree.
    assert request["store_fatal_ack"] is None
    # The action fields are flat beside the envelope, not nested under a query.
    assert "query" not in request


def test_a_reply_bound_to_another_request_is_never_read_as_queued(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    def respond(*, request: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        return {
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + "0" * 64,
            "status": "ok",
            "code": "ok",
            "payload": {"queued": True},
        }

    _install(monkeypatch, respond)

    with pytest.raises(NativeHookEvidenceWriterUnavailableError):
        writer.submit_native_decision_receipt({"receipt": "shaped"})


def test_a_resident_error_raises_the_store_exception_its_code_names(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(
        monkeypatch,
        _answer({"message": "bad evidence"}, status="error", code="native_guard_store_value_error"),
    )

    with pytest.raises(ValueError, match="bad evidence"):
        writer.submit_composio_discovery(
            harness="claude-code",
            payload={"tool_name": "mcp__composio__composio_search_tools"},
            succeeded=True,
        )


def test_reading_counters_consumes_the_mutation_count_once(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(monkeypatch, _answer({"running": True, "policy_mutations": 2, "store_fatal": None}))

    stats = writer.stats()

    # The signals are not counters; the caller takes them deliberately.
    assert "policy_mutations" not in stats
    assert "store_fatal" not in stats
    assert stats["running"] is True
    assert writer.take_policy_mutations() == 2
    assert writer.take_policy_mutations() == 0


def test_a_reported_fatal_store_runs_the_store_recovery_once(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    respond = _resident_holding_a_fatal_store({"running": True, "policy_mutations": 0})
    _install(monkeypatch, respond)

    writer.stats()

    recovered = writer._store.recovered
    assert len(recovered) == 1
    error = recovered[0]
    assert isinstance(error, sqlite3.DatabaseError)
    assert getattr(error, "sqlite_errorcode", None) == 11
    # The resident keeps the failure until this client names it, and the next
    # request is what names it.
    assert respond.sent[0]["store_fatal_ack"] is None
    writer.stats()
    assert respond.sent[1]["store_fatal_ack"] == _FATAL["id"]
    # One failure, one recovery: the acknowledgement ends it on both sides.
    assert len(writer._store.recovered) == 1
    writer.stats()
    assert respond.sent[2]["store_fatal_ack"] is None
    assert len(writer._store.recovered) == 1


def test_an_ordinary_counter_read_never_recovers_the_store(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(monkeypatch, _answer({"running": True, "policy_mutations": 0, "store_fatal": None}))

    writer.stats()

    assert writer._store.recovered == []


def test_stopping_sends_its_own_drain_budget_rather_than_either_default(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    respond = _answer({"drained": True, "policy_mutations": 1, "store_fatal": None})
    _install(monkeypatch, respond)

    assert writer.stop(timeout_seconds=0.5) is True
    assert respond.sent[0]["timeout_seconds"] == 0.5
    assert writer.take_policy_mutations() == 1


def test_a_recovery_that_fails_is_retried_rather_than_acknowledged(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts: list[BaseException] = []

    def recover(error: BaseException, **_kwargs: Any) -> bool:
        attempts.append(error)
        if len(attempts) == 1:
            raise OSError("quarantine failed")
        return True

    monkeypatch.setattr(writer._store, "_recover_fatal_sqlite_store", recover)
    respond = _resident_holding_a_fatal_store({"running": True, "policy_mutations": 0})
    _install(monkeypatch, respond)

    # The failed recovery is not an error the caller sees, and it is not an
    # acknowledgement either: the resident still holds the failure.
    writer.stats()
    assert len(attempts) == 1
    assert respond.sent[0]["store_fatal_ack"] is None

    writer.stats()
    assert len(attempts) == 2
    assert respond.sent[1]["store_fatal_ack"] is None

    writer.stats()
    assert len(attempts) == 2
    assert respond.sent[2]["store_fatal_ack"] == _FATAL["id"]


def test_a_failure_reported_on_a_submission_recovers_without_a_counter_read(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(monkeypatch, _resident_holding_a_fatal_store({"queued": True, "policy_mutations": 3}))

    assert writer.submit_native_decision_receipt({"decision_id": "d-1"}) is True

    assert len(writer._store.recovered) == 1
    assert writer.take_policy_mutations() == 3


def test_a_drain_result_survives_a_recovery_that_raises(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    def recover(_error: BaseException, **_kwargs: Any) -> bool:
        raise OSError("quarantine failed")

    monkeypatch.setattr(writer._store, "_recover_fatal_sqlite_store", recover)
    _install(monkeypatch, _answer({"drained": True, "policy_mutations": 0, "store_fatal": _FATAL}))

    # The writer has already left the resident's registry, so losing the drain
    # result to a recovery failure would lose it for good.
    assert writer.stop(timeout_seconds=0.5) is True


def test_a_writer_refusal_raises_the_writer_error_not_a_store_failure(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(monkeypatch, _answer({"message": "no writer"}, status="error", code="writer_unavailable"))

    with pytest.raises(NativeHookEvidenceWriterUnavailableError) as raised:
        writer.submit_native_decision_receipt({"decision_id": "d-1"})

    assert raised.value.reason == "native_hook_evidence_writer_writer_unavailable"


def test_a_start_builds_the_writer_before_any_hook_submits(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    respond = _answer({"running": True, "policy_mutations": 0, "store_fatal": None})
    _install(monkeypatch, respond)

    assert writer.start() is True

    # Building the writer is what replays its journal. The daemon asks for it
    # at startup so the first hook to record a decision does not wait for it.
    assert respond.sent[0]["action"] == "start"


def test_a_start_the_resident_refuses_is_reported_rather_than_raised(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(monkeypatch, _answer({"message": "no writer"}, status="error", code="writer_unavailable"))

    # Warming the writer is not the daemon's to fail on. A resident that
    # refuses here refuses the submission too, and that is where the caller
    # that is recording something learns it.
    assert writer.start() is False


def test_a_start_recovers_a_store_failure_the_resident_is_holding(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(monkeypatch, _resident_holding_a_fatal_store({"running": True, "policy_mutations": 1}))

    assert writer.start() is True

    # The reply carries the signals every reply carries, so the warm-up reads
    # them rather than leaving the failure for whatever calls next.
    assert len(writer._store.recovered) == 1
    assert writer.take_policy_mutations() == 1


def test_an_unreachable_resident_reads_as_a_writer_that_stopped_running() -> None:
    stats = native_hook_evidence_writer.unreachable_writer_stats()

    # A health reader treats a started writer that is not running as a fault.
    # A resident nobody can reach is that fault, not a reason to refuse the
    # whole health report.
    assert stats["started"] is True
    assert stats["running"] is False
    assert stats["degraded"] is True
