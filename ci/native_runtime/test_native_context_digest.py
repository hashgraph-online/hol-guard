"""Resident context-digest integration: real binary, real transport, full parity corpus."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import uuid4

from native_managed_test_support import environment
from native_managed_test_support import managed_runtime as _managed_runtime_fixture  # noqa: F401

from codex_plugin_scanner.guard.native_policy_snapshot import provision_native_policy_verifier_key
from codex_plugin_scanner.guard.native_resident_client import native_resident_client_request

_CORPUS = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "context-digest-parity" / "cases.v1.json"

_REQUEST_SCHEMA = "guard-context-digest-request.v1"
_RESULT_SCHEMA = "guard-context-digest-result.v1"


def _cases() -> dict[str, object]:
    value = json.loads(_CORPUS.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _op(
    runtime: Path,
    guard_home: Path,
    request: dict[str, object],
    *,
    expect_bound: bool = True,
) -> dict[str, object]:
    request_id = uuid4().hex
    body = {"schema": _REQUEST_SCHEMA, "request_id": request_id, **request}
    envelope = {"operation": "context_digest", "deadline_budget_ms": 5_000, "request": body}
    raw = native_resident_client_request(
        executable=runtime,
        guard_home=guard_home,
        environment=environment(guard_home),
        payload=json.dumps(envelope).encode("utf-8"),
        timeout_seconds=10.0,
    )
    assert raw is not None, "production native client did not return a bound response"
    value = json.loads(raw)
    assert isinstance(value, dict)
    assert value["schema"] == _RESULT_SCHEMA
    assert value["request_id"] == request_id
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if expect_bound:
        assert value["request_sha256"] == hashlib.sha256(canonical).hexdigest()
    return value


def test_resident_context_digest_component_cases(managed_runtime: tuple[Path, Path]) -> None:
    runtime, guard_home = managed_runtime
    provision_native_policy_verifier_key(guard_home, b"\x07" * 32)
    cases = _cases()["component_cases"]
    assert isinstance(cases, list) and cases
    for case in cases:
        divergent = case.get("diverges_from_python") is True
        result = _op(
            runtime,
            guard_home,
            {
                "kind": "build_approval_context_token",
                "components": {
                    **case["components"],
                    "extension_control_digest": case["extension_control_digest"],
                },
            },
            # Integers beyond u64 cannot round-trip through serde_json: the
            # worker's re-serialization diverges from the caller's bytes, so
            # the request digest cannot bind and the adapter rejects it.
            expect_bound=not divergent,
        )
        assert result["status"] == "ok", case["id"]
        assert result["code"] == "ok", case["id"]
        if divergent:
            assert result["token"] != case["token"], case["id"]
        else:
            assert result["token"] == case["token"], case["id"]


def test_resident_context_digest_value_cases(managed_runtime: tuple[Path, Path]) -> None:
    runtime, guard_home = managed_runtime
    provision_native_policy_verifier_key(guard_home, b"\x07" * 32)
    cases = _cases()["value_cases"]
    assert isinstance(cases, list) and cases
    for case in cases:
        kind = "configured_environment_hash" if case["domain"] == "environment" else "configured_headers_hash"
        result = _op(
            runtime,
            guard_home,
            {
                "kind": kind,
                "values": case["values"],
                "configured_keys": case["configured_keys"],
            },
        )
        # Truthy non-mapping inputs raised AttributeError in the retired
        # Python implementation; the worker rejects them with a typed error
        # which the adapter surfaces as TypeError at the same boundary.
        if case.get("error"):
            assert result["status"] == "error", case["id"]
            assert result["code"] == "native_context_values_invalid", case["id"]
            continue
        assert result["status"] == "ok", case["id"]
        assert result["digest"] == case["digest"], case["id"]


def test_resident_context_digest_argv_cases(managed_runtime: tuple[Path, Path]) -> None:
    runtime, guard_home = managed_runtime
    provision_native_policy_verifier_key(guard_home, b"\x07" * 32)
    cases = _cases()["argv_cases"]
    assert isinstance(cases, list) and cases
    for case in cases:
        result = _op(
            runtime,
            guard_home,
            {"kind": "launch_argv_digest", "argv": case["argv"]},
        )
        assert result["status"] == "ok", case["id"]
        assert result["digest"] == case["digest"], case["id"]


def test_resident_context_digest_validation_cases(managed_runtime: tuple[Path, Path]) -> None:
    runtime, guard_home = managed_runtime
    provision_native_policy_verifier_key(guard_home, b"\x07" * 32)
    cases = _cases()["validation_cases"]
    assert isinstance(cases, list) and cases
    for case in cases:
        result = _op(
            runtime,
            guard_home,
            {
                "kind": "validate_approval_context_tokens",
                "saved_token": case["saved_token"],
                "current_token": case["current_token"],
            },
        )
        assert result["status"] == "ok", case["id"]
        assert result.get("validation_reason") == case["reason"], case["id"]


def test_resident_context_digest_rejects_unknown_fields(managed_runtime: tuple[Path, Path]) -> None:
    runtime, guard_home = managed_runtime
    provision_native_policy_verifier_key(guard_home, b"\x07" * 32)
    body = {
        "schema": _REQUEST_SCHEMA,
        "request_id": uuid4().hex,
        "kind": "launch_argv_digest",
        "argv": ["hol-guard"],
        "unexpected": True,
    }
    raw = native_resident_client_request(
        executable=runtime,
        guard_home=guard_home,
        environment=environment(guard_home),
        payload=json.dumps({"operation": "context_digest", "deadline_budget_ms": 5_000, "request": body}).encode(
            "utf-8"
        ),
        timeout_seconds=10.0,
    )
    assert raw is not None
    # Strict per-variant decode rejects the whole envelope before dispatch.
    assert json.loads(raw) == {
        "error": "native_resident_request_invalid_json",
        "retryable": False,
    }


def test_resident_context_digest_rejects_non_json_components(
    managed_runtime: tuple[Path, Path],
) -> None:
    runtime, guard_home = managed_runtime
    provision_native_policy_verifier_key(guard_home, b"\x07" * 32)
    result = _op(
        runtime,
        guard_home,
        {
            "kind": "configured_environment_hash",
            "values": {"TOKEN": 3},
            "configured_keys": ["TOKEN"],
        },
    )
    assert result["status"] == "error"
    assert result["code"] == "native_context_values_invalid"
