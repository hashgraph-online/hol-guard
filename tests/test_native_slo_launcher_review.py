"""Source tests for real approval observation and strict launcher orchestration."""

from __future__ import annotations

import io
import json
import sys
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.hook_native_review_approval import queue_native_pre_tool_review
from scripts import native_slo_launcher_corpus as corpus
from scripts.native_slo_launcher_review import LauncherReviewFixture, approved_review_case, validate_resolution
from scripts.native_slo_priority_launchers import RegisteredLauncher
from scripts.native_slo_workloads import build_cases

from .test_native_review_policy_binding import _bind_receipt, _bound_edge
from .test_native_slo_launcher_approval import _result, _session


def _case(tmp_path, harness="claude-code"):
    return next(
        case
        for case in build_cases(tmp_path)
        if case.harness == harness and case.expected.reason_class == "review" and case.event == "PreToolUse"
    )


def _resolution(harness):
    result = {
        "state": "resolved",
        "request_id": "a" * 32,
        "resolution": "allow",
        "approval_durable": True,
        "authority": "ordinary_local_review",
        "matching": "exact_identity_and_new_row",
        "binding_present": True,
        "live_decision": [],
        "revalidation_routes": {},
        "continuation_status": "absent",
        "continuation_capability": "retry-only",
    }
    if harness == "codex":
        result.update(
            live_decision=[
                {
                    "request_id": "a" * 32,
                    "completed": True,
                    "action": "allow",
                    "replayed": False,
                    "fresh_allow_authorized": True,
                }
            ],
            native_evaluations=[{"decision": "deny", "policy_action": "review", "minimum_action": "review"}] * 2,
            continuation_status="resumed",
            continuation_capability="suspended-response",
        )
    return result


def test_delivery_allow_keeps_independent_native_review_expectation(tmp_path):
    for harness in ("claude-code", "codex"):
        original = _case(tmp_path / harness, harness)
        approved = approved_review_case(original)
        assert approved.native_expected is original.native_expected
        assert approved.native_expected.fields["minimum_action"] == "review"
        assert approved.expected.reason_class == "approved_review"
        if harness == "codex":
            assert approved.expected.fields == {"hookSpecificOutput.hookEventName": "PreToolUse"}
        else:
            assert approved.expected.fields["approval_reuse_status"] == "accepted"


@pytest.mark.parametrize(
    "change",
    [
        {"binding_present": False},
        {"approval_durable": False},
        {"state": "failed"},
        {"live_decision": []},
        {"continuation_status": "waiting"},
        {"continuation_capability": "retry-only"},
        {"revalidation_routes": {"native_fail_safe": 1}},
        {"revalidation_routes": {"native_resident": 1}},
        {"native_evaluations": []},
        {"native_evaluations": [{"decision": "allow", "policy_action": "allow", "minimum_action": "allow"}] * 2},
    ],
)
def test_sparse_codex_allow_cannot_substitute_for_real_completion(change):
    with pytest.raises(RuntimeError):
        validate_resolution(_resolution("codex") | change, harness="codex")


def test_fixture_observes_actual_codex_missing_authority_without_repairing_it(tmp_path):
    session, _ = _session(tmp_path)
    session.daemon._server.hook_process_runner = SimpleNamespace(stats=lambda: {"routes": {}})
    session.daemon._server.hook_worker._review_raw_hook_native = lambda **_kwargs: None
    fixture = LauncherReviewFixture(session)
    try:
        case = _case(session.workspace, "codex")
        begun = fixture.dispatch("launcher_approval_begin", {"harness": "codex", "payload": case.payload})
        edge = _bound_edge()
        edge["harness"] = edge["receipt"]["harness"] = "codex"
        _bind_receipt(edge)
        row = queue_native_pre_tool_review(
            session.store,
            harness="codex",
            payload=case.payload,
            native_result=edge["result"],
            workspace=session.workspace,
            guard_home=session.store.guard_home,
            verified_receipt=edge["receipt"],
        )
        assert row is not None
        resolved = _result(fixture.controller, begun["operation_id"])
        assert resolved["state"] == "resolved"
        from codex_plugin_scanner.guard.daemon import server

        actual = server.complete_codex_live_decision(
            session.store,
            request_id=row["request_id"],
            now=datetime.now(timezone.utc).isoformat(),
            fresh_allow_authorized=True,
        )
        assert actual == {"completed": False, "error": "exact_approval_authority_missing"}
        evidence = fixture.dispatch("launcher_approval_result", {"operation_id": begun["operation_id"]})
        assert evidence["continuation_capability"] == "retry-only"
        assert evidence["live_decision"][0]["error"] == "exact_approval_authority_missing"
        assert evidence["revalidation_routes"] == {}
        with pytest.raises(RuntimeError, match="continuation unproven"):
            validate_resolution(evidence, harness="codex")
    finally:
        fixture.close()


def test_new_native_observer_preserves_returns_and_restores_both_call_sites(tmp_path, monkeypatch):
    from scripts import native_slo_launcher_review as review

    session, _ = _session(tmp_path)
    edge = _bound_edge()
    completion = {"completed": True, "action": "allow"}

    def original_native(**_kwargs):
        return edge

    def original_complete(*_args, **_kwargs):
        return completion

    worker = session.daemon._server.hook_worker
    worker._review_raw_hook_native = original_native
    candidate_module = SimpleNamespace(complete_codex_live_decision=original_complete)
    monkeypatch.setattr(review, "import_module", lambda _name: candidate_module)
    fixture = LauncherReviewFixture(session)
    try:
        fixture._capture_completion()
        assert worker._review_raw_hook_native() is edge
        assert worker._review_raw_hook_native() is edge
        assert (
            candidate_module.complete_codex_live_decision(request_id="a" * 32, fresh_allow_authorized=True)
            is completion
        )
        assert len(fixture._native_evaluations) == 2
        assert fixture._native_evaluations[0]["minimum_action"] == edge["result"]["minimum_action"]
        assert fixture._completions[0]["completed"] is True
        assert fixture._completions[0]["fresh_allow_authorized"] is True
    finally:
        fixture.close()
    assert worker._review_raw_hook_native is original_native
    assert candidate_module.complete_codex_live_decision is original_complete


def test_registered_process_retains_stdout_and_exit_evidence_on_invalid_json(tmp_path, monkeypatch):
    case = _case(tmp_path, "codex")
    launcher = RegisteredLauncher(
        "codex", "PreToolUse", (sys.executable, "-c", "print('not-json')"), (), "a" * 64, tmp_path / "config.toml"
    )
    monkeypatch.setattr(corpus, "registered_launcher", lambda *_args: launcher)
    session = SimpleNamespace(root=tmp_path, workspace=tmp_path)
    observed = {}
    with pytest.raises(RuntimeError, match="stdout is not JSON"):
        corpus._run_registered(session, launcher, case, process_evidence=observed, approval_wait=True)
    assert observed["returncode"] == 0
    assert observed["stdout_bytes"] == len("not-json\n")
    assert len(observed["stdout_sha256"]) == 64
    assert observed["browser_opening"] == "suppressed"


def test_failed_counter_read_retains_offered_and_failure_without_fabricated_counts(tmp_path):
    def unavailable():
        raise RuntimeError("qualification metrics unavailable")

    session = SimpleNamespace(
        daemon=SimpleNamespace(
            _server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=SimpleNamespace(snapshot=unavailable)))
        )
    )
    launcher = RegisteredLauncher("codex", "PreToolUse", ("unused",), (), "a" * 64, tmp_path / "unused")
    evidence = io.StringIO()
    with pytest.raises(RuntimeError, match="metrics unavailable"):
        corpus._attempt(session, launcher, _case(tmp_path, "codex"), stage="ordinary", evidence=evidence)
    offered, failed = [json.loads(line) for line in evidence.getvalue().splitlines()]
    assert offered["status"] == "offered"
    assert failed["status"] == "failed"
    assert "routes_before" not in failed and "routes_after" not in failed
    assert failed["failure"]["diagnostic_digest"] == failed["routes_failure"]["diagnostic_digest"]


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_private_fixture_dispatches_review_sibling_and_always_closes_mixed(tmp_path, monkeypatch, cleanup_fails):
    from scripts import native_slo_daemon_fixture as daemon_fixture
    from scripts import native_slo_launcher_review as review
    from scripts import native_slo_mixed_server as mixed

    observed = []

    class Review:
        def __init__(self, _session):
            pass

        def dispatch(self, operation, request):
            observed.append((operation, request["operation_id"]))
            return {"state": "waiting"}

        def close(self):
            observed.append("review_closed")
            if cleanup_fails:
                raise RuntimeError("qualification review cleanup failed")

    monkeypatch.setattr(review, "LauncherReviewFixture", Review)
    monkeypatch.setattr(
        mixed, "MixedScenarioFixture", lambda _session: SimpleNamespace(close=lambda: observed.append("mixed_closed"))
    )
    monkeypatch.setattr(daemon_fixture, "_emit", observed.append)
    monkeypatch.setattr(
        daemon_fixture.sys,
        "stdin",
        SimpleNamespace(buffer=io.BytesIO(b'{"op":"launcher_approval_result","operation_id":"a"}\n{"op":"close"}\n')),
    )
    session = SimpleNamespace(
        root=tmp_path,
        workspace=tmp_path,
        guard_home=tmp_path,
        daemon=SimpleNamespace(port=1, _server=SimpleNamespace(auth_token="synthetic")),
        readiness_ms=1,
    )
    if cleanup_fails:
        with pytest.raises(RuntimeError, match="cleanup failed"):
            daemon_fixture._serve_session(session, None)
    else:
        daemon_fixture._serve_session(session, None)
    assert ("launcher_approval_result", "a") in observed
    assert {"state": "waiting"} in observed
    assert observed[-3:] == ["review_closed", "mixed_closed", {"state": "progress", "stage": "cleanup"}]


def test_ordinary_corpus_retains_review_obligation_without_starting_approval(tmp_path, monkeypatch):
    cases = [
        _case(tmp_path, "codex"),
        next(
            case
            for case in build_cases(tmp_path)
            if case.harness == "codex"
            and case.event == "PreToolUse"
            and case.setup == "normal"
            and case.expected.reason_class == "benign"
            and corpus._selected(case)
        ),
    ]

    class Fixture:
        workspace = tmp_path

        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

    observed = []

    def attempt(_session, _launcher, case, **_kwargs):
        observed.append(case.expected.reason_class)
        return "native_resident", 1.0

    monkeypatch.setattr(corpus, "DaemonFixture", Fixture)
    monkeypatch.setattr(corpus, "_IMPLEMENTED_SETUPS", {"normal"})
    monkeypatch.setattr(corpus, "build_cases", lambda *_args, **_kwargs: cases)
    monkeypatch.setattr(corpus, "_attempt", attempt)
    monkeypatch.setattr(
        corpus,
        "install_priority_launchers",
        lambda *_args: [RegisteredLauncher("codex", "PreToolUse", ("unused",), (), "a" * 64, tmp_path / "unused")],
    )
    result = corpus.run_registered_contract_corpus(tmp_path / "runtime", evidence_file=tmp_path / "attempts.jsonl")
    assert observed == ["benign"]
    assert result["scope"] == "priority_fault_corpus"
    assert "browser_approval_continuation" in result["remaining"]
    assert result["review_harnesses"] == []


@pytest.mark.parametrize("codex_completed", [True, False])
def test_corpus_executes_both_review_flows_and_keeps_failed_attempts(tmp_path, monkeypatch, codex_completed):
    cases = [_case(tmp_path / "claude", "claude-code"), _case(tmp_path / "codex", "codex")]
    routes = {"native_resident": 0}
    attempts = []

    class Fixture:
        def __init__(self, *_args, **_kwargs):
            self.root = self.workspace = self.guard_home = tmp_path
            self.daemon = SimpleNamespace(
                _server=SimpleNamespace(
                    hook_worker=SimpleNamespace(metrics=SimpleNamespace(snapshot=lambda: {"routes": dict(routes)}))
                )
            )
            self.harness = ""

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def control(self, operation, **kwargs):
            if operation == "launcher_approval_begin":
                self.harness = kwargs["harness"]
                return {"state": "waiting", "operation_id": "b" * 32}
            if operation == "launcher_approval_result":
                result = _resolution(self.harness)
                if self.harness == "codex" and not codex_completed:
                    result["live_decision"] = []
                return result
            if operation == "case_before":
                return {}
            if operation == "case_result":
                return {
                    "setup": {
                        "isolated_store": True,
                        "policy_ack_current": True,
                        "effective_policy_allow": True,
                        "python_oracle_disabled": True,
                        "fault_scope": "none",
                    },
                    "native_result": dict(cases[0].native_expected.fields),
                }
            raise AssertionError(operation)

    def launch(_session, _launcher, case, *, process_evidence, approval_wait):
        assert approval_wait
        attempts.append((case.harness, case.expected.reason_class))
        routes["native_resident"] += 2 if case.harness == "codex" else 1
        process_evidence.update(returncode=0, stdout_bytes=10, stdout_sha256="c" * 64)
        response = {}
        for key, value in case.expected.fields.items():
            if "." in key:
                parent, child = key.split(".", 1)
                response.setdefault(parent, {})[child] = value
            else:
                response[key] = value
        for key in case.expected.nonempty_fields:
            response[key] = "synthetic"
        return response, 1.0

    monkeypatch.setattr(corpus, "DaemonFixture", Fixture)
    monkeypatch.setattr(corpus, "_IMPLEMENTED_SETUPS", {"normal"})
    monkeypatch.setattr(corpus, "build_cases", lambda *_args, **_kwargs: cases)
    monkeypatch.setattr(corpus, "_run_registered", launch)
    monkeypatch.setattr(
        corpus,
        "install_priority_launchers",
        lambda *_args: [
            RegisteredLauncher(harness, "PreToolUse", ("synthetic",), (), "d" * 64, tmp_path / "unused")
            for harness in ("claude-code", "codex")
        ],
    )
    evidence_file = tmp_path / "attempts.jsonl"
    if codex_completed:
        result = corpus.run_registered_approval_corpus(tmp_path / "runtime", evidence_file=evidence_file)
        assert result["validated_cases"] == 2
        assert result["validated_attempts"] == 3
        assert "browser_approval_continuation" not in result["remaining"]
        assert result["qualification_complete"] is False
        assert result["scope"] == "priority_approval"
    else:
        with pytest.raises(RuntimeError, match="continuation unproven"):
            corpus.run_registered_approval_corpus(tmp_path / "runtime", evidence_file=evidence_file)
    assert attempts == [("claude-code", "review"), ("claude-code", "approved_review"), ("codex", "approved_review")]
    rows = [json.loads(line) for line in evidence_file.read_text().splitlines()]
    assert len([row for row in rows if row["status"] == "offered"]) == 3
    outcomes = [row for row in rows if row["status"] != "offered"]
    assert all(row["native_action"] == "review" for row in outcomes)
    assert all(
        row["routes_after"]["native_resident"] - row["routes_before"]["native_resident"]
        == (2 if row["harness"] == "codex" else 1)
        for row in outcomes
    )
    assert outcomes[-1]["status"] == ("validated" if codex_completed else "failed")
