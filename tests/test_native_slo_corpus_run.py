from __future__ import annotations

import hashlib
import json
from contextlib import nullcontext
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_slo_corpus_run as corpus
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_failure import FixtureFailureError, failure_evidence


@pytest.mark.parametrize("encoded,status", [(b'{"hook_event_name":', 400), (b"x" * 1_000_001, 413)])
def test_transport_rejection_distinguishes_declared_length_from_delivered_malformed_bytes(
    monkeypatch: pytest.MonkeyPatch, encoded: bytes, status: int
) -> None:
    connections = []

    class Connection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.headers = {}
            self.sent = b""
            self.closed = False
            connections.append(self)

        def putrequest(self, *_args: object) -> None:
            pass

        def putheader(self, key: str, value: str) -> None:
            self.headers[key] = value

        def endheaders(self) -> None:
            pass

        def send(self, value: bytes) -> None:
            self.sent += value

        def getresponse(self) -> BytesIO:
            response = BytesIO(
                b'{"error":"request_body_too_large"}' if status == 413 else b'{"error":"invalid_request_body"}'
            )
            response.status = status
            return response

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(corpus, "HTTPConnection", Connection)
    session = SimpleNamespace(
        guard_home="synthetic",
        workspace="synthetic",
        daemon=SimpleNamespace(port=1234, _server=SimpleNamespace(auth_token="synthetic")),
    )
    response, observed_status = corpus._transport_boundary(session, "pi", encoded)
    connection = connections[0]
    assert observed_status == status
    assert response["error"] == ("request_body_too_large" if status == 413 else "invalid_request_body")
    assert int(connection.headers["Content-Length"]) == len(encoded)
    assert connection.sent == (b"" if status == 413 else encoded)
    assert connection.closed is True


@pytest.mark.parametrize("refused", (False, True))
def test_failed_corpus_case_retains_worker_diagnostic_through_outer_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, refused: bool
) -> None:
    from scripts import native_slo_workloads as workloads
    from scripts.native_slo_publisher_diagnostic import policy_refusal_diagnostic

    case = next(
        case
        for case in workloads.build_cases(tmp_path)
        if case.setup == "normal" and case.case_id == "omp/PostToolUse/block/max"
    )
    routes = {}
    metrics = SimpleNamespace(snapshot=lambda: {"routes": dict(routes)})
    diagnostic = {
        "capture_context": "native_worker_wrapper",
        "client_after_value": "native_client_timed_out",
        "client_before_state": "absent",
        "client_code_attribution": "context_transition",
        "caller_expired_before": False,
        "caller_expired_after": True,
        "policy_generation_valid": True,
        "publisher_cache": "captured",
        "publisher_acked": True,
    }
    refusal = policy_refusal_diagnostic(
        "HOL Guard could not prepare the native policy safely. native_policy_windows_acl_verify_failed."
    )
    reason = "native_policy_not_ready" if refused else "native_post_tool_unavailable"

    def request(*_args: object) -> tuple[dict[str, str], float]:
        routes["native_fail_safe"] = 1
        return {"decision": "allow", "policy_action": "allow", "reason_code": reason}, 1.0

    session = SimpleNamespace(
        workspace=tmp_path,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=metrics))),
        request=request,
        control=lambda _operation: {
            "setup": {},
            "native_result": None,
            "native_call_diagnostic": None if refused else diagnostic,
            "native_call_count": 0 if refused else 1,
            "native_completed_call_count": 0 if refused else 1,
            **({"policy_refusal_diagnostic": refusal, "policy_refusal_count": 1} if refused else {}),
        },
    )
    monkeypatch.setattr(corpus, "DaemonFixture", lambda *_args, **_kwargs: nullcontext(session))
    monkeypatch.setattr(corpus, "wait_for_route_corpus", lambda *_args, **_kwargs: metrics.snapshot())
    monkeypatch.setattr(workloads, "corpus_manifest", lambda: {"setup_requirements": ["normal"]})
    monkeypatch.setattr(workloads, "build_cases", lambda _workspace, **_kwargs: (case,))
    monkeypatch.setattr(workloads, "validate_setup", lambda *_args: None)
    with pytest.raises(FixtureFailureError) as caught:
        corpus.run_contract_corpus(tmp_path)
    report = json.loads(json.dumps(assert_privacy_safe({"failure": failure_evidence(caught.value)})))
    detail = report["failure"]
    assert detail["case"] == case.case_id.replace("/", ".") and detail["field"] == "route"
    assert detail["native_call_count"] == (0 if refused else 1)
    assert detail["native_completed_call_count"] == (0 if refused else 1)
    assert detail["native_call_diagnostic"] == (None if refused else diagnostic)
    assert detail["policy_refusal_diagnostic"] == (refusal if refused else None)
    assert detail["policy_refusal_count"] == (1 if refused else None)
    assert detail["observed_semantics"]["native"]["available"] is False
    assert (
        detail["observed_semantics"]["delivered"]["reason_code_digest"]
        == hashlib.sha256(json.dumps(reason).encode()).hexdigest()
    )
