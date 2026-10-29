"""The resident health transport forwards a question and validates the answer.

Nothing here lets Python decide the resident is healthy. Every case either
returns the resident's own reply unchanged or returns ``None``, which says the
question went unanswered.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_resident_health as transport
from codex_plugin_scanner.guard.adapters.diagnostic_probes import without_command_probes
from codex_plugin_scanner.guard.cli import doctor_native_runtime as doctor


def _counters(**overrides: Any) -> dict[str, Any]:
    counters: dict[str, Any] = {
        "served_requests": 42,
        "service_micros_total": 1_000_000,
        "service_micros_max": 90_000,
        "request_bytes_total": 8192,
        "request_bytes_max": 512,
        "auth_failures": 0,
        "frame_errors": 1,
        "deadline_exceeded": 0,
        "digest_mismatches": 0,
        "panics": 0,
    }
    counters.update(overrides)
    return counters


def _reply(**overrides: Any) -> dict[str, Any]:
    reply: dict[str, Any] = {
        "schema": "guard-resident-health-result.v1",
        "request_id": "",
        "request_sha256": "sha256:" + "0" * 64,
        "status": "serving",
        "protocol_version": 2,
        "runtime_version": "3.59.0",
        "build_sha": "unknown",
        "target": "aarch64-macos",
        "uptime_ms": 1234,
        "evaluation": {"workers": 15, "queue_capacity": 24, "queued": 2, "queued_max": 24},
        "control": {"workers": 1, "queue_capacity": 8, "queued": 0, "queued_max": 3},
        "overloaded_requests": 3,
        "counters": _counters(),
    }
    reply.update(overrides)
    return reply


class _Resident:
    """A stub resident that answers one request with the bytes it was given."""

    def __init__(self, response: bytes | None) -> None:
        self.response = response
        self.envelopes: list[dict[str, Any]] = []
        self.diagnostic: bool | None = None

    def install(self, monkeypatch: pytest.MonkeyPatch, *, features: list[str] | None = None) -> None:
        if features is None:
            features = ["resident-protocol-v2", transport.RESIDENT_HEALTH_FEATURE]
        status = SimpleNamespace(
            available=True,
            compatible=True,
            identity=SimpleNamespace(path=Path("/native"), sha256="0" * 64),
            capabilities=SimpleNamespace(features=features),
        )
        monkeypatch.setattr(transport, "native_runtime_status", lambda **_: status)
        monkeypatch.setattr(transport, "_isolated_environment", dict)
        monkeypatch.setattr(transport, "native_resident_client_request", self.request)

    def request(self, **kwargs: Any) -> bytes | None:
        envelope = json.loads(kwargs["payload"].decode("utf-8"))
        self.envelopes.append(envelope)
        self.diagnostic = kwargs.get("diagnostic")
        return self.response


def _answering(monkeypatch: pytest.MonkeyPatch, reply: dict[str, Any]) -> _Resident:
    """A resident that echoes the caller's request id, as the real one does."""

    resident = _Resident(None)

    def request(**kwargs: Any) -> bytes:
        envelope = json.loads(kwargs["payload"].decode("utf-8"))
        resident.envelopes.append(envelope)
        resident.diagnostic = kwargs.get("diagnostic")
        answered = dict(reply)
        if answered["request_id"] == "":
            answered["request_id"] = envelope["request"]["request_id"]
        return json.dumps(answered).encode("utf-8")

    resident.install(monkeypatch)
    monkeypatch.setattr(transport, "native_resident_client_request", request)
    return resident


def test_forwards_the_operation_on_the_control_lane_and_returns_the_resident_answer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    resident = _answering(monkeypatch, _reply())

    result = transport.native_resident_health(guard_home=tmp_path)

    assert result is not None
    assert result["status"] == "serving"
    assert result["control"] == {"workers": 1, "queue_capacity": 8, "queued": 0, "queued_max": 3}
    assert result["overloaded_requests"] == 3
    # A lane that has drained still says how deep it has been, so a caller
    # reading a quiet resident can tell it from one that was never loaded.
    assert result["evaluation"]["queued_max"] == 24
    assert result["counters"]["served_requests"] == 42
    assert result["counters"]["frame_errors"] == 1
    envelope = resident.envelopes[0]
    assert envelope["operation"] == "resident_health"
    assert envelope["request"]["schema"] == "guard-resident-health-request.v1"
    assert envelope["deadline_budget_ms"] >= 1
    # The request says nothing about the work the resident is doing.
    assert set(envelope["request"]) == {"schema", "request_id"}


def test_an_older_runtime_without_the_feature_is_never_asked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    resident = _Resident(json.dumps(_reply(request_id="rh-1")).encode("utf-8"))
    resident.install(monkeypatch, features=["resident-protocol-v2"])

    assert transport.native_resident_health(guard_home=tmp_path) is None
    assert resident.envelopes == []


def test_a_resident_that_does_not_answer_reads_as_unanswered(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    resident = _Resident(None)
    resident.install(monkeypatch)

    assert transport.native_resident_health(guard_home=tmp_path) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"schema": "guard-resident-health-result.v2"},
        {"status": "ready"},
        {"protocol_version": -1},
        {"protocol_version": 3},
        {"uptime_ms": True},
        {"evaluation": {"workers": 15}},
        {"control": {"workers": 1, "queue_capacity": -1, "extra": 0}},
        {"build_sha": ""},
        {"request_sha256": ""},
        # A counters block that is there must be whole: a missing total would
        # read as a resident that has never failed that way.
        {"counters": {name: 0 for name in list(_counters())[:-1]}},
        {"counters": _counters(panics=-1)},
        {"counters": _counters(served_requests=True)},
        {"counters": _counters(service_micros_total="1000")},
        {"counters": []},
    ],
)
def test_a_reply_that_is_not_the_contract_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, overrides: dict[str, Any]
) -> None:
    _answering(monkeypatch, _reply(**overrides))

    assert transport.native_resident_health(guard_home=tmp_path) is None


def test_a_runtime_without_the_counters_still_answers(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Python and the runtime ship as separate artifacts and skew either way.

    A resident built before the aggregate counters existed reports the lanes
    and nothing else. Refusing that reply would report a serving resident as
    unreachable, which is the one answer this transport must never invent.
    """
    reply = _reply()
    del reply["counters"]
    reply["evaluation"] = {"workers": 15, "queue_capacity": 24}
    _answering(monkeypatch, reply)

    result = transport.native_resident_health(guard_home=tmp_path)

    assert result is not None
    assert "counters" not in result
    assert result["evaluation"] == {"workers": 15, "queue_capacity": 24}


def test_a_newer_runtime_that_reports_more_is_still_read(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # The other direction of the same skew: a field this Python does not know
    # about is carried through rather than taken as a malformed reply.
    _answering(
        monkeypatch,
        _reply(
            restarts=7,
            counters=_counters(circuit_opened=2),
            control={"workers": 1, "queue_capacity": 8, "queued": 0, "queued_max": 3, "rejected": 4},
        ),
    )

    result = transport.native_resident_health(guard_home=tmp_path)

    assert result is not None
    assert result["restarts"] == 7
    assert result["counters"]["circuit_opened"] == 2
    assert result["control"]["rejected"] == 4


def test_a_reply_for_someone_elses_request_is_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _answering(monkeypatch, _reply(request_id="rh-somebody-else"))

    assert transport.native_resident_health(guard_home=tmp_path) is None


def test_the_question_is_asked_as_a_diagnostic(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A health question must leave the hook path's restart hold alone."""
    resident = _answering(monkeypatch, _reply())

    assert transport.native_resident_health(guard_home=tmp_path) is not None
    assert resident.diagnostic is True


@pytest.mark.parametrize("failure", [OSError("no socket"), RuntimeError("no runtime"), ValueError("bad state")])
def test_a_transport_failure_reads_as_unanswered(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: Exception
) -> None:
    """One optional line of a report must not take the whole report down."""
    resident = _Resident(None)
    resident.install(monkeypatch)

    def fail(**_: Any) -> bytes:
        raise failure

    monkeypatch.setattr(transport, "native_resident_client_request", fail)

    assert transport.native_resident_health(guard_home=tmp_path) is None


def test_an_unreadable_runtime_status_reads_as_unanswered(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fail(**_: Any) -> Any:
        raise OSError("the runtime could not be read")

    monkeypatch.setattr(transport, "native_runtime_status", fail)

    assert transport.native_resident_health(guard_home=tmp_path) is None


def test_a_refusal_frame_is_not_mistaken_for_an_answer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    resident = _Resident(json.dumps({"error": "native_overloaded", "retryable": True}).encode("utf-8"))
    resident.install(monkeypatch)

    assert transport.native_resident_health(guard_home=tmp_path) is None


def test_doctor_asks_a_live_resident_and_reports_the_answer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    asked: list[Path] = []

    def health(*, guard_home: Path, timeout_seconds: float = 2.0) -> dict[str, Any]:
        asked.append(guard_home)
        return _reply(request_id="rh-1")

    monkeypatch.setattr(transport, "native_resident_health", health)
    monkeypatch.setattr(
        doctor,
        "native_resident_presence",
        lambda *_: {"live": True, "owner_lock_held": False, "generations": 1},
    )
    monkeypatch.setattr(doctor, "_passive_runtime_sha256", lambda: "0" * 64)

    section = doctor.native_runtime_section(tmp_path)

    assert asked == [tmp_path]
    resident = section["resident"]
    assert isinstance(resident, dict)
    assert resident["serving"]["status"] == "serving"


def test_doctor_never_starts_a_resident_that_is_not_already_serving(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def health(**_: Any) -> dict[str, Any]:
        raise AssertionError("doctor must stay passive")

    monkeypatch.setattr(transport, "native_resident_health", health)
    monkeypatch.setattr(
        doctor,
        "native_resident_presence",
        lambda *_: {"live": False, "owner_lock_held": None, "generations": 0},
    )
    monkeypatch.setattr(doctor, "_passive_runtime_sha256", lambda: "0" * 64)

    section = doctor.native_runtime_section(tmp_path)

    resident = section["resident"]
    assert isinstance(resident, dict)
    assert "serving" not in resident


def test_a_read_only_caller_never_asks_the_resident(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Reading the feature list runs the binary, which a passive report forbids."""

    def health(**_: Any) -> dict[str, Any]:
        raise AssertionError("a passive report must not run the runtime")

    monkeypatch.setattr(transport, "native_resident_health", health)
    monkeypatch.setattr(
        doctor,
        "native_resident_presence",
        lambda *_: {"live": True, "owner_lock_held": False, "generations": 1},
    )
    monkeypatch.setattr(doctor, "_passive_runtime_sha256", lambda: "0" * 64)

    with without_command_probes():
        section = doctor.native_runtime_section(tmp_path)

    resident = section["resident"]
    assert isinstance(resident, dict)
    assert "serving" not in resident
