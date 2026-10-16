"""Evidence that each generated Pi extension hook reached native Guard once.

On POSIX hosts the generated extension runs the installed runtime's
``pi-hook-bridge`` for every hook instead of posting to the daemon itself. It
keeps its own loopback ``fetch`` on Windows, without a runtime that advertises
the bridge, or when ``HOL_GUARD_PI_HOOK_BRIDGE=fetch``. The probe reads which
lane the generated source took and holds every case to exactly one Guard
request on that lane, carrying the daemon's exact proof in its reply.

A bridged hook is answered by the live resident directly or handed to the
daemon, which must route it to the native resident. The resident's own
per-harness answer count, carried to the daemon on each evidence drain page,
plus the daemon's native route count must equal the case count, with no
other daemon route.

With no reachable review service the extension must fail every hook closed.
It may run the Guard CLI only to recover the daemon, never to review a hook.
A recovery call carries no case ID, so the probe runs each unavailable-service
case alone and credits it with the CLI records that its run appended.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

try:
    from ci.native_runtime.probe_daemon_calls import ProbeError
except ModuleNotFoundError:  # Run directly as a script from its own directory.
    from probe_daemon_calls import ProbeError  # type: ignore[no-redef]

TEXT_LIMIT = 12_000
FETCH = "fetch"
BRIDGE = "pi-hook-bridge"
_HARNESS = "omp"
_PROOF_KEYS = ("decision", "model_output_action", "reviewed_output_sha256", "observe_mode", "policy_action")
_TRANSPORT_KEYS = {
    FETCH: ("method", "pathname", "status"),
    BRIDGE: ("harness", "exit_code", "status"),
}
_RUNTIME_LINE = re.compile(r"^const GUARD_NATIVE_HOOK_RUNTIME: string \| null = (.+);$", re.MULTILINE)

# Records each `pi-hook-bridge` run next to the loopback fetch evidence. The
# generated extension imports `spawn` by name, so the builtin export is
# replaced and resynchronised before the extension is imported. Only the
# daemon's proof fields are copied out of the bridge's reply.
NODE_BRIDGE_CAPTURE_SOURCE = """\
import { createRequire, syncBuiltinESMExports } from "node:module";
const childProcess = createRequire(import.meta.url)("node:child_process");
const originalSpawn = childProcess.spawn;
const BRIDGE_PROOF_KEYS = [
  "decision", "model_output_action", "reviewed_output_sha256", "observe_mode", "policy_action",
];
childProcess.spawn = function (command, args, ...rest) {
  const child = originalSpawn.call(this, command, args, ...rest);
  if (!Array.isArray(args) || args[0] !== "pi-hook-bridge") return child;
  const record = { transport: "pi-hook-bridge", harness: null, exit_code: null, status: null };
  try {
    const config = JSON.parse(String(args[1]));
    if (config && typeof config.harness === "string") record.harness = config.harness;
  } catch {}
  guardEvidence.push(record);
  let stdout = "";
  child.stdout?.on("data", (chunk) => {
    if (stdout.length <= 8_388_608) stdout += String(chunk);
  });
  child.once("close", (code) => {
    record.exit_code = code;
    try {
      const envelope = JSON.parse(stdout.trim());
      if (Number.isInteger(envelope?.status)) record.status = envelope.status;
      const body = typeof envelope?.body === "string" ? JSON.parse(envelope.body) : null;
      if (body && typeof body === "object" && !Array.isArray(body)) {
        for (const key of BRIDGE_PROOF_KEYS) {
          const value = body[key];
          if (typeof value === "string" || typeof value === "boolean") record[key] = value;
        }
      }
    } catch {}
  });
  return child;
};
syncBuiltinESMExports();
"""


def text_digest(content: list[dict[str, Any]]) -> tuple[str, int, str]:
    text = "".join(item["text"] for item in content if item.get("type") == "text" and isinstance(item.get("text"), str))
    return hashlib.sha256(text.encode("utf-8")).hexdigest(), len(text), text[:TEXT_LIMIT]


def generated_transport(source: str) -> str:
    """The lane a generated extension sends its hooks on."""

    declared = _RUNTIME_LINE.findall(source)
    if len(declared) != 1:
        raise ProbeError("generated extension does not declare its native hook runtime")
    try:
        runtime = json.loads(declared[0])
    except ValueError as exc:
        raise ProbeError("generated extension declares an unreadable native hook runtime") from exc
    if runtime is None:
        return FETCH
    if not isinstance(runtime, str) or not runtime:
        raise ProbeError("generated extension declares an invalid native hook runtime")
    return BRIDGE


def _requests_by_case(
    requests: list[dict[str, Any]],
    results: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    transport: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    if len(requests) != len(cases):
        raise ProbeError(f"generated extension did not make exactly one Guard request per real case over {transport}")
    result_ids = [result.get("id") for result in results]
    if len(results) != len(cases) or any(not isinstance(result_id, str) for result_id in result_ids):
        raise ProbeError("Guard request evidence could not correlate every real case")
    if len(set(result_ids)) != len(result_ids):
        raise ProbeError("Guard request evidence found duplicate real case IDs")
    by_id = {result["id"]: result for result in results}
    expected_ids = {str(case["id"]) for case in cases}
    if set(by_id) != expected_ids:
        raise ProbeError("Guard request evidence could not correlate every real case")
    grouped: dict[str, list[dict[str, Any]]] = {}
    for request in requests:
        case_id = request.get("case_id")
        if not isinstance(case_id, str):
            raise ProbeError("Guard request evidence is missing its case correlation")
        grouped.setdefault(case_id, []).append(request)
    if set(grouped) != expected_ids or any(len(case_requests) != 1 for case_requests in grouped.values()):
        raise ProbeError("Guard request evidence did not contain exactly one response per real case")
    return {case_id: case_requests[0] for case_id, case_requests in grouped.items()}, by_id


def assert_guard_requests(
    requests: list[dict[str, Any]],
    results: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    *,
    transport: str = FETCH,
) -> dict[str, dict[str, Any]]:
    """Validate the one redacted Guard reply correlated to each generated case."""

    if transport not in _TRANSPORT_KEYS:
        raise ProbeError(f"unknown generated extension transport: {transport}")
    transport_keys = _TRANSPORT_KEYS[transport]
    allowed_keys = {"case_id", "transport", *transport_keys, *_PROOF_KEYS}
    by_case, by_id = _requests_by_case(requests, results, cases, transport)
    evidence: dict[str, dict[str, Any]] = {}
    for case in cases:
        case_id = str(case["id"])
        request = by_case[case_id]
        if request.get("transport") != transport:
            raise ProbeError(f"generated extension did not use the {transport} lane for {case_id}")
        if set(request) - allowed_keys:
            raise ProbeError(f"Guard request evidence contains unapproved fields for {case_id}")
        if transport == FETCH and (request.get("method") != "POST" or request.get("pathname") != "/v1/hooks/omp"):
            raise ProbeError(f"generated extension used an unexpected daemon route for {case_id}")
        if transport == BRIDGE and (request.get("harness") != _HARNESS or request.get("exit_code") != 0):
            raise ProbeError(f"native hook bridge did not complete for {case_id}")
        if request.get("status") != 200:
            raise ProbeError(f"daemon hook response was not successful for {case_id}")
        result = by_id[case_id]
        digest, chars, _ = text_digest(case["content"])
        preserved = result.get("preserved") is True
        expected_proof: dict[str, Any] = {"decision": "allow"}
        if preserved:
            expected_proof.update(model_output_action="allow_original", reviewed_output_sha256=digest)
        elif case_id == "large-nonsource":
            expected_proof["model_output_action"] = "replace_with_reviewed_excerpt"
        else:
            raise ProbeError(f"{case_id} was not preserved and is not an excerpt case")
        for key, expected in expected_proof.items():
            if request.get(key) != expected:
                raise ProbeError(f"daemon response proof mismatch for {case_id}: {key}")
        evidence[case_id] = {
            "case_id": case_id,
            "transport": transport,
            **{key: request[key] for key in transport_keys},
            **expected_proof,
            "sha256": digest,
            "chars": chars,
            "preserved": preserved,
        }
    return evidence


def bridge_route_counts(metrics: object, counters: object) -> dict[str, int]:
    """Daemon native routes, other daemon routes, and resident direct answers."""

    routes = metrics.get("routes") if isinstance(metrics, Mapping) else None
    resident = counters.get("resident") if isinstance(counters, Mapping) else None
    harness = resident.get(_HARNESS) if isinstance(resident, Mapping) else None
    counts = {"native_resident": 0, "daemon_other": 0, "resident_direct": 0}
    if isinstance(routes, Mapping):
        for route, count in routes.items():
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ProbeError("daemon hook metrics contained invalid route counts")
            counts["native_resident" if route == "native_resident" else "daemon_other"] += count
    if isinstance(harness, Mapping):
        answered = harness.get("answer", 0)
        if isinstance(answered, bool) or not isinstance(answered, int) or answered < 0:
            raise ProbeError("resident direct counters contained an invalid answer count")
        counts["resident_direct"] = answered
    return counts


def assert_bridge_routes(counts: Mapping[str, int], expected: int) -> dict[str, int]:
    if (
        counts.get("daemon_other") != 0
        or counts.get("resident_direct", 0) + counts.get("native_resident", 0) != expected
    ):
        raise ProbeError(f"bridged cases did not each reach the native resident exactly once: {dict(counts)}")
    return dict(counts)


def wait_for_bridge_native_routes(daemon: Any, expected: int, *, timeout_seconds: float = 10.0) -> dict[str, int]:
    worker = getattr(getattr(daemon, "_server", None), "hook_worker", None)
    metrics = getattr(getattr(worker, "metrics", None), "snapshot", None)
    counters = getattr(getattr(worker, "hook_counters", None), "snapshot", None)
    if not callable(metrics) or not callable(counters):
        raise ProbeError("installed daemon did not expose hook route metrics and resident counters")
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, int] = {}
    while time.monotonic() < deadline:
        last = bridge_route_counts(metrics(), counters())
        if last["daemon_other"] or last["resident_direct"] + last["native_resident"] >= expected:
            return assert_bridge_routes(last, expected)
        time.sleep(0.02)
    raise ProbeError(f"timed out waiting for native bridge route evidence: {last}")


def capture_log_size(path: Path) -> int:
    """Where the CLI capture log ends now, so a run's own records can be read later."""

    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def read_capture_records(path: Path, start: int = 0) -> list[dict[str, Any]]:
    """Parse the CLI capture log records written at or after byte ``start``."""

    try:
        lines = path.read_bytes()[start:].decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ProbeError(f"CLI wrapper did not write its capture log: {exc}") from exc
    records: list[dict[str, Any]] = []
    for line in lines:
        try:
            record = json.loads(line)
            case_id = record["case_id"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ProbeError("CLI wrapper capture log contains invalid JSON") from exc
        if not isinstance(case_id, str) or not isinstance(record, dict):
            raise ProbeError("CLI wrapper capture log has an invalid record")
        records.append(record)
    return records


def assert_unavailable_results(
    results: list[dict[str, Any]],
    records: Mapping[str, list[dict[str, Any]]],
    cases: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Each case failed closed, and its own run only ever tried daemon recovery once.

    ``records`` maps each case ID to the CLI records appended while that case ran.
    """

    expected_ids = {str(case["id"]) for case in cases}
    result_ids = [result.get("id") for result in results]
    if len(results) != len(expected_ids) or any(not isinstance(result_id, str) for result_id in result_ids):
        raise ProbeError("generated extension did not return every unavailable-service case")
    if len(set(result_ids)) != len(result_ids):
        raise ProbeError("generated extension returned duplicate unavailable-service case IDs")
    by_id = {result["id"]: result for result in results}
    if set(by_id) != expected_ids:
        raise ProbeError("generated extension did not return every unavailable-service case")
    if not set(records) <= expected_ids:
        raise ProbeError("CLI capture records name an unexpected unavailable-service case")
    for case_id in sorted(expected_ids):
        case_records = records.get(case_id, [])
        if any(record.get("invocation_kind") != "recovery" for record in case_records):
            raise ProbeError(f"generated extension ran a Guard CLI review instead of failing closed: {case_id}")
        if len(case_records) != 1:
            raise ProbeError(f"generated extension did not try daemon recovery once for {case_id}: {len(case_records)}")
    evidence: dict[str, dict[str, Any]] = {}
    for case_id, result in by_id.items():
        returned = result.get("result")
        if result.get("preserved") is True:
            raise ProbeError(f"unavailable review service silently preserved output: {case_id}")
        if not isinstance(returned, dict) or returned.get("isError") is not True:
            raise ProbeError(f"unavailable review service did not visibly block output: {case_id}")
        if result.get("input_content_unchanged") is not True:
            raise ProbeError(f"unavailable review service mutated the input event: {case_id}")
        evidence[case_id] = {"preserved": False, "is_error": True}
    return evidence


__all__ = [
    "BRIDGE",
    "FETCH",
    "NODE_BRIDGE_CAPTURE_SOURCE",
    "TEXT_LIMIT",
    "ProbeError",
    "assert_bridge_routes",
    "assert_guard_requests",
    "assert_unavailable_results",
    "bridge_route_counts",
    "capture_log_size",
    "generated_transport",
    "read_capture_records",
    "text_digest",
    "wait_for_bridge_native_routes",
]
