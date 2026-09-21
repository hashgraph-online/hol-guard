from __future__ import annotations

import hashlib
import json
import stat
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import native_slo_phase_run as run


class Session:
    setup = "normal"

    def __init__(self, mode: str = "normal") -> None:
        self.mode = mode
        self.operations: list[str] = []
        self.requests: list[int] = []
        self.routes = {"native_resident": 0}
        self.native: dict[str, object] | None = None
        self.instrumented = False
        self.group_attempts = 0
        self.group_bytes = 0
        self.metrics = SimpleNamespace(snapshot=lambda: {"routes": dict(self.routes)})
        self.daemon = SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=self.metrics)))

    def control(self, operation: str) -> dict[str, object]:
        self.operations.append(operation)
        if operation == "phases_start":
            self.instrumented = True
            self.group_attempts = self.group_bytes = 0
            return {"started": self.mode != "start_ack_missing"}
        if operation == "case_before":
            self.native = None
            return {"reset": self.mode != "reset_ack_missing"}
        if operation == "case_result":
            return {
                "setup": {"isolated_store": True, "effective_policy_allow": True, "policy_ack_current": True},
                "native_result": self.native,
            }
        if operation == "phases_finish":
            self.instrumented = False
            if self.mode == "finish_failure":
                raise RuntimeError("synthetic finish failure")
            report = {
                "schema": "hol-guard-python-phase-diagnostics.v2",
                "scope": "diagnostic_instrumented_run",
                "headline_timing_eligible": False,
                "discarded_samples": 0,
                "discarded_series_updates": 0,
                "by_route": {
                    "claude-code.PostToolUse": {
                        phase: {"count": self.group_attempts}
                        for phase in (
                            "daemon_hook_inclusive",
                            "envelope_encode",
                            "native_client_inclusive",
                            "edge_json_loads",
                            "edge_json_dumps",
                        )
                    },
                    "claude-code.transport_unclassified": {
                        "http_body_read": {"work": {"returned_bytes": self.group_bytes}}
                    },
                },
            }
            if self.mode == "empty_spans":
                report["by_route"] = {}
            if self.mode == "missing_wire":
                report["by_route"]["claude-code.transport_unclassified"]["http_body_read"]["work"][
                    "returned_bytes"
                ] -= 1
            if self.mode == "dropped_timings":
                report["discarded_samples"] = 1
            return report
        raise AssertionError("unexpected operation")

    def request(self, harness: str, request: dict[str, object]) -> tuple[dict[str, object], float]:
        assert self.instrumented and harness == "claude-code"
        encoded = json.dumps(request, separators=(",", ":")).encode()
        self.requests.append(len(encoded))
        self.group_attempts += 1
        self.group_bytes += len(encoded)
        text = request["tool_response"][0]["text"]
        blocked = text.startswith("ghp_")
        reason = "output_secret_match" if blocked else "output_scan_allow"
        self.native = {
            "decision": "deny" if blocked else "allow",
            "model_output_action": "block" if blocked else "allow_original",
            "policy_action": "block" if blocked else "allow",
            "reason_code": reason,
        }
        if not blocked:
            self.native["reviewed_output_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        delivered = {
            "policy_action": "block" if blocked else "allow",
            "hookSpecificOutput": {"hookEventName": "PostToolUse"},
        }
        if blocked:
            delivered.update(decision="block", model_output_action="block", reason_code=reason, **{"continue": True})
        route = "native_fail_safe" if self.mode == "wrong_route" else "native_resident"
        self.routes[route] = self.routes.get(route, 0) + (2 if self.mode == "two_routes" else 1)
        if self.mode == "wrong_delivery":
            delivered["policy_action"] = "review"
        if self.mode == "wrong_native":
            self.native["policy_action"] = "block" if not blocked else "allow"
        if self.mode == "missing_native":
            self.native = None
        if self.mode == "request_failure":
            raise OSError("private request contents ghp_not_a_credential")
        return delivered, 0.25


def rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_four_fixed_cases_reach_exact_real_adapter_serialization_and_http_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
    from scripts import native_slo_session

    sent: list[str] = []

    def authenticated(**kwargs: object) -> str:
        sent.append(kwargs["data"])
        return "{}"

    monkeypatch.setattr(native_slo_session, "authenticated_claude_hook_response", authenticated)
    cases = run.phase_cases()
    assert [case.wire_bytes for case in cases] == [1024, 1024, 1_000_000, 1_000_000]
    for case in cases:
        assert "guard_source_ref" not in case.payload
        native_slo_session._request(
            SimpleNamespace(),
            guard_home=tmp_path,
            workspace=tmp_path,
            harness=case.harness,
            request_payload=case.payload,
        )
        encoded = sent[-1].encode("utf-8")
        assert len(encoded) == case.wire_bytes
        handler = object.__new__(_GuardDaemonHandler)
        handler.headers = Message()
        handler.headers["Content-Length"] = str(len(encoded))
        handler.headers["Content-Type"] = "application/json"
        monkeypatch.setattr(handler, "_read_request_body", lambda _length, encoded=encoded: (encoded, None))
        assert handler._load_request_body() == (case.payload, None)
    maximum = json.loads(sent[-1])
    maximum["tool_response"][0]["text"] += "x"
    too_large = json.dumps(maximum, separators=(",", ":")).encode()
    assert len(too_large) == _GuardDaemonHandler._MAX_BODY_BYTES + 1
    handler.headers.replace_header("Content-Length", str(len(too_large)))
    monkeypatch.setattr(handler, "_read_request_body", lambda _length: pytest.fail("overlimit body must not be read"))
    assert handler._load_request_body() == ({}, "request_body_too_large")


def test_separate_reports_validate_every_actual_outcome_and_private_journal(tmp_path: Path) -> None:
    evidence = tmp_path / "phase.jsonl"
    session = Session()
    result = run.measure_installed_phases(session, 2, evidence)
    assert result["attempted"] == result["validated"] == 8
    assert session.requests == [1024] * 4 + [1_000_000] * 4
    assert session.operations.count("phases_start") == session.operations.count("phases_finish") == 2
    assert session.operations.count("case_before") == session.operations.count("case_result") == 8
    assert result["headline_timing_eligible"] is False
    assert result["large_source_reference_included"] is False
    assert result["journal_sha256"] == hashlib.sha256(evidence.read_bytes()).hexdigest()
    records = rows(evidence)
    offered = [row for row in records if row["status"] == "offered"]
    terminal = [
        row for row in records if row["schema"] == "hol-guard.phase-attempt.v1" and row["status"] == "validated"
    ]
    assert len(offered) == len(terminal) == 8
    assert all(row["route"] == "native_resident" and row["http_request_ms"] == 0.25 for row in terminal)
    assert all(row["request_call_ms"] >= 0 for row in terminal)
    assert {row["native"]["semantic"]["decision"] for row in terminal} == {"allow", "deny"}
    assert {row["delivered"]["semantic"]["policy_action"] for row in terminal} == {"allow", "block"}
    assert all(len(row["native"]["sha256"]) == 64 for row in terminal)
    assert "const guard_value" not in evidence.read_text()
    assert "ghp_" not in evidence.read_text()
    if run.os.name != "nt":
        assert stat.S_IMODE(evidence.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "mode", ["wrong_delivery", "wrong_native", "missing_native", "wrong_route", "two_routes", "request_failure"]
)
def test_failed_attempt_is_retained_with_available_native_route_and_delivery(tmp_path: Path, mode: str) -> None:
    evidence = tmp_path / "failed.jsonl"
    session = Session(mode)
    with pytest.raises((AssertionError, RuntimeError, OSError)):
        run.measure_installed_phases(session, 2, evidence)
    records = rows(evidence)
    terminal = [row for row in records if row["schema"] == "hol-guard.phase-attempt.v1" and row["status"] == "failed"]
    assert len(terminal) == 1
    assert terminal[0]["request_started"] is True
    assert terminal[0]["routes_after"] != terminal[0]["routes_before"]
    assert terminal[0]["failures"]
    assert terminal[0]["request_call_ms"] >= 0
    if mode == "request_failure":
        assert "delivered" not in terminal[0]
        assert terminal[0]["native"]["semantic"]["decision"] == "allow"
    else:
        assert "delivered" in terminal[0]
    assert session.operations[-1] == "phases_finish"
    assert session.requests == [1024]
    assert records[-1]["status"] == "failed"
    assert "ghp_" not in evidence.read_text()
    assert "private request contents" not in evidence.read_text()


@pytest.mark.parametrize(
    "mode",
    ["empty_spans", "missing_wire", "dropped_timings", "finish_failure", "start_ack_missing", "reset_ack_missing"],
)
def test_missing_attribution_or_acknowledgment_cannot_return_success(tmp_path: Path, mode: str) -> None:
    evidence = tmp_path / "failed.jsonl"
    session = Session(mode)
    with pytest.raises(RuntimeError):
        run.measure_installed_phases(session, 1, evidence)
    records = rows(evidence)
    assert records[-1]["status"] == "failed"
    assert "phases_finish" in session.operations
    assert not session.instrumented
    if mode == "reset_ack_missing":
        assert "case_result" not in session.operations
        terminal = next(
            row for row in records if row["schema"] == "hol-guard.phase-attempt.v1" and row["status"] == "failed"
        )
        assert terminal["capture_reset_acknowledged"] is False
        assert terminal["request_started"] is False
        assert "native" not in terminal
    if mode in {"empty_spans", "missing_wire", "dropped_timings"}:
        assert any(row.get("report") is not None for row in records)


def test_partial_setup_failure_has_terminal_record_and_no_stale_native_claim(tmp_path: Path) -> None:
    session = Session()
    del session.daemon
    evidence = tmp_path / "failed.jsonl"
    with pytest.raises(AttributeError):
        run.measure_installed_phases(session, 1, evidence)
    terminal = next(
        row for row in rows(evidence) if row["schema"] == "hol-guard.phase-attempt.v1" and row["status"] == "failed"
    )
    assert terminal["request_started"] is False
    assert terminal["native"]["observed"] is False


@pytest.mark.parametrize("count", [0, 101, True, 1.5])
def test_count_bound_rejects_before_file_or_fixture_work(tmp_path: Path, count: object) -> None:
    session = Session()
    evidence = tmp_path / "unused.jsonl"
    with pytest.raises(ValueError):
        run.measure_installed_phases(session, count, evidence)
    assert not evidence.exists()
    assert session.operations == []


def test_headline_session_without_native_tap_cannot_be_instrumented(tmp_path: Path) -> None:
    session = Session()
    session.setup = None
    with pytest.raises(ValueError, match="normal capture"):
        run.measure_installed_phases(session, 1, tmp_path / "unused")
    assert session.operations == []


def test_journal_refuses_overwrite_and_reserves_terminal_space(tmp_path: Path) -> None:
    evidence = tmp_path / "existing.jsonl"
    evidence.write_text("keep")
    session = Session()
    with pytest.raises(FileExistsError):
        run.measure_installed_phases(session, 1, evidence)
    assert evidence.read_text() == "keep"
    assert session.operations == []
    with run._Journal(tmp_path / "bounded.jsonl") as journal:
        journal.records = run._MAX_RECORDS - 4
        with pytest.raises(RuntimeError, match="retain next attempt"):
            journal.reserve_attempt()
        assert journal.size == 0


def test_unexpected_semantic_strings_keep_identity_without_echoing_text() -> None:
    evidence = run._semantic_evidence(
        {"decision": "private unexpected output", "reason_code": "wrong value", "continue": True}
    )
    assert evidence["semantic"]["continue"] is True
    assert evidence["semantic"]["decision"]["unexpected_value"]["sha256"]
    assert "private unexpected output" not in json.dumps(evidence)
    assert "wrong value" not in json.dumps(evidence)


def test_engine_bypass_with_allow_shaped_delivery_cannot_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    session = Session()
    request = session.request

    def bypass(harness: str, value: dict[str, object]) -> tuple[dict[str, object], float]:
        result = request(harness, value)
        session.routes["native_resident"] -= 1
        session.native = None
        return result

    monkeypatch.setattr(session, "request", bypass)
    monkeypatch.setattr(run, "wait_for_route_corpus", lambda metrics, **_kwargs: metrics.snapshot())
    evidence = tmp_path / "bypass.jsonl"
    with pytest.raises(AssertionError, match=":route"):
        run.measure_installed_phases(session, 1, evidence)
    failed = next(
        row for row in rows(evidence) if row["schema"] == "hol-guard.phase-attempt.v1" and row["status"] == "failed"
    )
    assert failed["route"] == "engine_bypassed"
    assert failed["delivered"]["semantic"]["policy_action"] == "allow"
    assert failed["routes_before"] == failed["routes_after"]
    assert failed["native"]["observed"] is False


def test_changed_request_size_fails_before_an_http_attempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cases = run.phase_cases()
    cases[0].payload["tool_response"][0]["text"] += "x"
    monkeypatch.setattr(run, "phase_cases", lambda: cases)
    session = Session()
    evidence = tmp_path / "changed.jsonl"
    with pytest.raises(RuntimeError, match="changed wire size"):
        run.measure_installed_phases(session, 1, evidence)
    assert session.requests == []
    assert not any(row["schema"] == "hol-guard.phase-attempt.v1" for row in rows(evidence))
    assert session.operations[-1] == "phases_finish"
