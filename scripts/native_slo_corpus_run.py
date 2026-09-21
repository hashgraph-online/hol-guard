"""Execute frozen semantic/fault cases through a private installed daemon."""

from __future__ import annotations

import hashlib
import json
import urllib.parse
from collections import Counter
from collections.abc import Mapping
from http.client import HTTPConnection
from pathlib import Path

from scripts.native_probe_receipts import wait_for_route_corpus
from scripts.native_slo_adapter import route_counts
from scripts.native_slo_daemon_fixture import DaemonFixture, witnessed_route
from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from scripts.native_slo_semantic_diagnostic import semantic_diagnostic

_IMPLEMENTED_SETUPS = frozenset(
    {
        "normal",
        "watch",
        "unavailable",
        "watch_unavailable",
        "off",
        "integrity",
        "queue_bytes",
        "review_queue_failed",
        "expired",
        "revoked",
    }
)


def _transport_boundary(
    session: DaemonFixture, harness: str, request_payload: Mapping[str, object] | bytes
) -> tuple[Mapping[str, object], int]:
    query = urllib.parse.urlencode({"home": str(session.guard_home), "workspace": str(session.workspace)})
    encoded_request = (
        request_payload
        if isinstance(request_payload, bytes)
        else json.dumps(request_payload, separators=(",", ":")).encode()
    )
    connection = HTTPConnection("127.0.0.1", session.daemon.port, timeout=5)
    try:
        connection.putrequest("POST", f"/v1/hooks/{harness}?{query}")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("X-Guard-Token", session.daemon._server.auth_token)
        connection.putheader("Content-Length", str(len(encoded_request)))
        connection.endheaders()
        # The server rejects an oversized declared length before body ingress.
        # Waiting for that response avoids a client-side broken pipe while
        # sending bytes the server correctly refuses to read.
        if len(encoded_request) <= 1_000_000:
            connection.send(encoded_request)
        with connection.getresponse() as opened:
            status = opened.status
            encoded = opened.read(256 * 1024 + 1)
    finally:
        connection.close()
    if len(encoded) > 256 * 1024:
        raise RuntimeError("qualification transport response exceeded bound")
    response = json.loads(encoded)
    if not isinstance(response, Mapping):
        raise RuntimeError("qualification transport response was not an object")
    return response, status


def run_contract_corpus(runtime: Path) -> dict[str, object]:
    from scripts.native_slo_workloads import (
        build_cases,
        corpus_manifest,
        platform_scope_summary,
        validate_case,
        validate_native_result,
        validate_setup,
    )

    manifest = corpus_manifest()
    setups = sorted(manifest["setup_requirements"])
    counted: set[str] = set()
    validated: list[str] = []
    counters = {
        name: Counter()
        for name in ("harness", "event", "size", "setup", "delivered", "surface", "http_status", "route")
    }
    semantic = 0
    syntax_rejections = 0
    for setup in setups:
        if setup not in _IMPLEMENTED_SETUPS:
            continue
        with DaemonFixture(runtime, setup=setup) as session:
            cases = build_cases(session.workspace)
            counted.update(case.case_id for case in cases)
            metrics = session.daemon._server.hook_worker.metrics
            for case in cases:
                if case.setup != setup:
                    continue
                session.control("case_before")
                before = route_counts(metrics.snapshot())
                if case.expected_http_status != 200:
                    response, http_status = _transport_boundary(session, case.harness, case.payload)
                else:
                    response, _elapsed = session.request(case.harness, case.payload)
                    http_status = 200
                if case.expected_route == "engine_bypassed":
                    after = route_counts(metrics.snapshot())
                else:
                    after = route_counts(wait_for_route_corpus(metrics, expected=sum(before.values()) + 1))
                route = witnessed_route(before, after)
                evidence = session.control("case_result")
                try:
                    validate_setup(case, evidence["setup"])
                    validate_case(case, response, route, http_status=http_status)
                    validate_native_result(case, evidence["native_result"])
                except AssertionError as error:
                    detail = failure_evidence(error)
                    detail["observed_semantics"] = semantic_diagnostic(response, evidence["native_result"], cases)
                    detail["native_call_diagnostic"] = evidence.get("native_call_diagnostic")
                    detail["native_call_count"] = evidence.get("native_call_count")
                    detail["native_completed_call_count"] = evidence.get("native_completed_call_count")
                    detail["policy_refusal_diagnostic"] = evidence.get("policy_refusal_diagnostic")
                    detail["policy_refusal_count"] = evidence.get("policy_refusal_count")
                    raise FixtureFailureError(detail) from error
                validated.append(case.case_id)
                semantic += int(case.semantic_sample)
                for name, value in (
                    ("harness", case.harness),
                    ("event", case.canonical_event),
                    ("size", case.size_class),
                    ("setup", case.setup),
                    ("delivered", case.expected.decision),
                    ("surface", case.surface),
                    ("http_status", str(http_status)),
                    ("route", route),
                ):
                    counters[name][value] += 1
            if setup == "normal":
                for encoded in (b'{"hook_event_name":', b'{"hook_event_name":"\xff"}'):
                    before = route_counts(metrics.snapshot())
                    response, status = _transport_boundary(session, "pi", encoded)
                    after = route_counts(metrics.snapshot())
                    if (
                        status != 400
                        or response != {"error": "invalid_request_body"}
                        or witnessed_route(before, after) != "engine_bypassed"
                    ):
                        raise RuntimeError("malformed transport fixture was not rejected before evaluation")
                    syntax_rejections += 1
    missing = sorted(set(setups) - _IMPLEMENTED_SETUPS)
    if not counted or not validated:
        raise RuntimeError("qualification contract corpus was empty")
    platform_scope = platform_scope_summary(cases, validated)
    return {
        "schema": "hol-guard.native-contract-corpus-run.v1",
        "boundary": "DAEMON_INGRESS",
        "oracle_digest": hashlib.sha256(Path(__file__).with_name("native_slo_workloads.py").read_bytes()).hexdigest(),
        "manifest_digest": hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "validated_digest": hashlib.sha256(json.dumps(sorted(validated), separators=(",", ":")).encode()).hexdigest(),
        "declared_cases": len(counted),
        "validated_cases": len(validated),
        "semantic_observations": semantic,
        "syntax_rejections": syntax_rejections,
        "oversize_transport_semantics": "declared_length_rejected_before_body_transfer",
        "platform_scope": platform_scope,
        "complete": len(validated) == len(counted) and not platform_scope["missing_scopes"],
        "implemented_scope_passed": True,
        "remaining_setups": missing,
        "coverage": {name: dict(values) for name, values in counters.items()},
        "latency_claim": "semantic_preflight_no_tail_claim",
        "installed_wrapper_claim": "separate_launcher_measurement_required",
    }
