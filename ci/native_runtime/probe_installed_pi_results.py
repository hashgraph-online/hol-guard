"""Installed Pi probe results helpers; dependencies remain bound to its public entry point."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .probe_installed_pi_api import probe_api


def _read_records(path: Path) -> dict[str, list[dict[str, Any]]]:
    _api = probe_api()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise _api.ProbeError(f"CLI wrapper did not write its capture log: {exc}") from exc
    grouped: dict[str, list[dict[str, Any]]] = {}
    for line in lines:
        try:
            record = _api.json.loads(line)
            case_id = record["case_id"]
        except (KeyError, TypeError, ValueError) as exc:
            raise _api.ProbeError("CLI wrapper capture log contains invalid JSON") from exc
        if not isinstance(case_id, str) or not isinstance(record, dict):
            raise _api.ProbeError("CLI wrapper capture log has an invalid record")
        grouped.setdefault(case_id, []).append(record)
    return grouped


def _payload_from_record(record: Mapping[str, Any]) -> dict[str, Any]:
    _api = probe_api()
    try:
        raw = _api.base64.b64decode(str(record["stdin_b64"]), validate=True)
        payload = _api.json.loads(raw.decode("utf-8"))
    except (KeyError, ValueError, UnicodeDecodeError) as exc:
        raise _api.ProbeError("CLI wrapper captured invalid request payload") from exc
    if not isinstance(payload, dict):
        raise _api.ProbeError("CLI wrapper captured a non-object request payload")
    return payload


def _response_from_record(record: Mapping[str, Any]) -> dict[str, Any] | None:
    _api = probe_api()
    try:
        stdout = _api.base64.b64decode(str(record["stdout_b64"]), validate=True).decode("utf-8")
    except (KeyError, ValueError, UnicodeDecodeError) as exc:
        raise _api.ProbeError("CLI wrapper captured invalid stdout") from exc
    for line in reversed(stdout.splitlines()):
        try:
            value = _api.json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and "decision" in value:
            return value
    return None


def _assert_real_results(
    results: list[dict[str, Any]],
    cases: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    _api = probe_api()
    result_ids = [result.get("id") for result in results]
    if len(results) != len(cases) or any(not isinstance(result_id, str) for result_id in result_ids):
        raise _api.ProbeError("generated extension did not return every real case")
    if len(set(result_ids)) != len(result_ids):
        raise _api.ProbeError("generated extension returned duplicate real case IDs")
    by_id = {result["id"]: result for result in results}
    expected_ids = {str(case["id"]) for case in cases}
    if set(by_id) != expected_ids:
        raise _api.ProbeError("generated extension did not return every real case")
    evidence: dict[str, dict[str, Any]] = {}
    for case in cases:
        case_id = str(case["id"])
        result = by_id[case_id]
        digest, chars, excerpt = _api._text_digest(case["content"])
        canonical_digest = _api._canonical_content_digest(case["content"])
        if (
            result.get("input_content_before_sha256") != canonical_digest
            or result.get("input_content_after_sha256") != canonical_digest
        ):
            raise _api.ProbeError(f"{case_id} mutated the canonical input event")
        preserved = result.get("preserved") is True
        if preserved:
            if result.get("input_content_unchanged") is not True:
                raise _api.ProbeError(f"{case_id} mutated the canonical input event")
        elif case_id != "large-nonsource":
            raise _api.ProbeError(f"{case_id} did not preserve the exact reviewed output")
        else:
            returned = result.get("result")
            content = returned.get("content") if isinstance(returned, dict) else None
            first = content[0] if isinstance(content, list) and content else None
            text = first.get("text") if isinstance(first, dict) else None
            if not isinstance(text, str) or text != excerpt:
                raise _api.ProbeError("large-nonsource did not return the exact bounded reviewed excerpt")
        evidence[case_id] = {
            "sha256": digest,
            "chars": chars,
            "excerpt_chars": len(excerpt),
            "preserved": preserved,
            "input_content_unchanged": result.get("input_content_unchanged") is True,
        }
    return evidence


def _assert_fetch_evidence(
    fetches: list[dict[str, Any]],
    results: list[dict[str, Any]],
    cases: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Validate redacted daemon responses correlated to each generated case."""
    _api = probe_api()
    allowed_keys = {
        "case_id",
        "method",
        "pathname",
        "status",
        "decision",
        "model_output_action",
        "reviewed_output_sha256",
        "observe_mode",
        "policy_action",
    }
    if len(fetches) != len(cases):
        raise _api.ProbeError("generated extension did not make exactly one daemon request per real case")
    result_ids = [result.get("id") for result in results]
    if len(results) != len(cases) or any(not isinstance(result_id, str) for result_id in result_ids):
        raise _api.ProbeError("daemon fetch evidence could not correlate every real case")
    if len(set(result_ids)) != len(result_ids):
        raise _api.ProbeError("daemon fetch evidence found duplicate real case IDs")
    by_id = {result["id"]: result for result in results}
    expected_ids = {str(case["id"]) for case in cases}
    if set(by_id) != expected_ids:
        raise _api.ProbeError("daemon fetch evidence could not correlate every real case")
    fetches_by_case: dict[str, list[dict[str, Any]]] = {}
    for fetch in fetches:
        case_id = fetch.get("case_id")
        if not isinstance(case_id, str):
            raise _api.ProbeError("daemon fetch evidence is missing its case correlation")
        fetches_by_case.setdefault(case_id, []).append(fetch)
    if set(fetches_by_case) != expected_ids or any(len(case_fetches) != 1 for case_fetches in fetches_by_case.values()):
        raise _api.ProbeError("daemon fetch evidence did not contain exactly one response per real case")
    evidence: dict[str, dict[str, Any]] = {}
    for case in cases:
        case_id = str(case["id"])
        fetch = fetches_by_case[case_id][0]
        if set(fetch) - allowed_keys:
            raise _api.ProbeError(f"daemon fetch evidence contains unapproved fields for {case_id}")
        if fetch.get("method") != "POST" or fetch.get("pathname") != "/v1/hooks/omp":
            raise _api.ProbeError(f"generated extension used an unexpected daemon route for {case_id}")
        if fetch.get("status") != 200:
            raise _api.ProbeError(f"daemon hook response was not successful for {case_id}")
        result = by_id[case_id]
        digest, chars, _ = _api._text_digest(case["content"])
        preserved = result.get("preserved") is True
        if preserved:
            expected_proof = {
                "decision": "allow",
                "model_output_action": "allow_original",
                "reviewed_output_sha256": digest,
            }
        else:
            expected_proof = {
                "decision": "allow",
                "model_output_action": "replace_with_reviewed_excerpt",
            }
            if case_id != "large-nonsource":
                raise _api.ProbeError(f"{case_id} was not preserved and is not an excerpt case")
        for key, expected in expected_proof.items():
            if fetch.get(key) != expected:
                raise _api.ProbeError(f"daemon response proof mismatch for {case_id}: {key}")
        evidence[case_id] = {
            "case_id": case_id,
            "method": fetch["method"],
            "pathname": fetch["pathname"],
            "status": fetch["status"],
            **expected_proof,
            "sha256": digest,
            "chars": chars,
            "preserved": preserved,
        }
    return evidence


def _assert_native_route_metrics(snapshot: Mapping[str, Any], expected: int) -> dict[str, int]:
    _api = probe_api()
    routes = snapshot.get("routes")
    if not isinstance(routes, _api.Mapping):
        raise _api.ProbeError("daemon hook metrics did not expose route counts")
    normalized: dict[str, int] = {}
    for route, count in routes.items():
        if not isinstance(route, str) or not isinstance(count, int) or count < 0:
            raise _api.ProbeError("daemon hook metrics contained invalid route counts")
        normalized[route] = count
    if normalized.get("native_resident") != expected or sum(normalized.values()) != expected:
        raise _api.ProbeError(f"positive daemon cases were not all native_resident: {normalized}")
    return normalized


def _wait_for_native_route_metrics(daemon: Any, expected: int, *, timeout_seconds: float = 5.0) -> dict[str, int]:
    _api = probe_api()
    metrics = getattr(getattr(daemon, "_server", None), "hook_worker", None)
    metrics = getattr(metrics, "metrics", None)
    snapshot = getattr(metrics, "snapshot", None)
    if not callable(snapshot):
        raise _api.ProbeError("installed daemon did not expose hook route metrics")
    deadline = _api.time.monotonic() + timeout_seconds
    last_routes: dict[str, int] = {}
    while _api.time.monotonic() < deadline:
        current = snapshot()
        if isinstance(current, _api.Mapping):
            routes = current.get("routes")
            if isinstance(routes, _api.Mapping):
                last_routes = {str(route): int(count) for route, count in routes.items() if isinstance(count, int)}
            if last_routes.get("native_resident") == expected and sum(last_routes.values()) == expected:
                return _api._assert_native_route_metrics(current, expected)
        _api.time.sleep(0.01)
    raise _api.ProbeError(f"timed out waiting for native resident route metrics: {last_routes}")


def _assert_no_positive_cli_fallback(path: Path) -> None:
    _api = probe_api()
    if path.exists():
        raise _api.ProbeError("positive generated extension unexpectedly used the CLI fallback")


def _assert_negative_results(
    results: list[dict[str, Any]],
    records: dict[str, list[dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    _api = probe_api()
    expected_ids = {str(case["id"]) for case in _api._negative_cases()}
    result_ids = [result.get("id") for result in results]
    if len(results) != len(expected_ids) or any(not isinstance(result_id, str) for result_id in result_ids):
        raise _api.ProbeError("generated extension did not return every malformed-result case")
    if len(set(result_ids)) != len(result_ids):
        raise _api.ProbeError("generated extension returned duplicate malformed-result case IDs")
    by_id = {result["id"]: result for result in results}
    if set(by_id) != expected_ids:
        raise _api.ProbeError("generated extension did not return every malformed-result case")
    evidence: dict[str, dict[str, Any]] = {}
    for case_id, result in by_id.items():
        matching = records.get(case_id, [])
        if not matching:
            raise _api.ProbeError(f"negative CLI wrapper was not invoked for {case_id}")
        record = matching[-1]
        if case_id == "negative-nonzero-allow" and record.get("returncode") == 0:
            raise _api.ProbeError("negative nonzero CLI case unexpectedly exited zero")
        preserved = result.get("preserved") is True
        response: dict[str, Any] | None = None
        if case_id == "negative-observe":
            response = _api._response_from_record(record)
            if record.get("returncode") != 0:
                raise _api.ProbeError("explicit observe response exited nonzero")
            if not preserved or not isinstance(response, dict):
                raise _api.ProbeError("explicit observe response was not preserved")
            if response.get("decision") != "allow" or response.get("observe_mode") is not True:
                raise _api.ProbeError("explicit observe response lacked canonical allow metadata")
        elif preserved:
            raise _api.ProbeError(f"malformed result silently preserved output: {case_id}")
        else:
            returned = result.get("result")
            if not isinstance(returned, dict) or returned.get("isError") is not True:
                raise _api.ProbeError(f"malformed result was not visibly blocked: {case_id}")
        evidence[case_id] = {
            "cli_invocations": len(matching),
            "preserved": preserved,
            "observe_mode": (
                response.get("observe_mode") if case_id == "negative-observe" and isinstance(response, dict) else None
            ),
            "is_error": bool(isinstance(result.get("result"), dict) and result["result"].get("isError")),
        }
    return evidence
